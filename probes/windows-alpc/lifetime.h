// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

// Names are diagnostic witnesses only. No resource name goes over the transport.
static void event_name(char *path, size_t size, const char *name, const char *suffix)
{
    snprintf(path, size, "Local\\%s-%s", name, suffix);
}

static void expect_object(const char *name, const char *suffix, int present)
{
    char path[256];
    event_name(path, sizeof(path), name, suffix);
    ULONGLONG deadline = GetTickCount64() + 5000;
    for (;;) {
        HANDLE h = OpenEventA(SYNCHRONIZE, FALSE, path);
        if (h) CloseHandle(h);
        else require(GetLastError() == ERROR_FILE_NOT_FOUND, "object lookup error");
        if ((h != NULL) == present) return;
        require(GetTickCount64() < deadline,
                present ? "queued transfer retains object" : "transfer object released");
        Sleep(1);
    }
}

static HANDLE barrier(const char *name, const char *suffix)
{
    char path[256];
    event_name(path, sizeof(path), name, suffix);
    HANDLE event = CreateEventA(NULL, TRUE, FALSE, path);
    require(event != NULL, "diagnostic barrier");
    return event;
}

static void await(HANDLE event)
{
    require(WaitForSingleObject(event, 10000) == WAIT_OBJECT_0, "barrier deadline");
}

static void ping(HANDLE port)
{
    const uint32_t get_features[3] = {1, 1, 0};
    send_message(port, get_features, sizeof(get_features), NULL, 0);
}

static void pong(HANDLE listener, HANDLE peer)
{
    Received r;
    for (;;) {
        NTSTATUS s = receive(listener, &r);
        check(s, "live connection receive");
        require(s != STATUS_TIMEOUT_VALUE, "live connection deadline");
        int type = r.message.head.type & 0xff;
        if (type == TYPE_DATAGRAM) break;
        require(r.context == 1 && (type == TYPE_CANCELLED || type == TYPE_CLOSED),
                "closed connection notification");
        release_message(listener, &r);
    }
    require(r.count == 0 && r.context == 2, "other connection remains usable");
    send_message(peer, r.message.data, r.message.head.data_length, NULL, 0);
    release_message(listener, &r);
}

static int lifetime(const char *role, const char *name, const char *which)
{
    int serve = strcmp(role, "server") == 0;
    int partial = strcmp(which, "partial") == 0;
    int queued = strcmp(which, "queued") == 0;
    int reverse = strcmp(which, "reverse") == 0;
    int rights = strcmp(which, "rights") == 0;
    int invalid = strcmp(which, "invalid") == 0;
    int waitable = strcmp(which, "waitable") == 0;
    require(partial || queued || reverse || rights || invalid || waitable, "known case");
    HANDLE ready = barrier(name, "ready"), proceed = barrier(name, "proceed");
    HANDLE finished = barrier(name, "finished");
    HANDLE done = barrier(name, "done");
    Received r;
    if (serve) {
        use_waitable_listener = waitable;
        HANDLE listener = listen_port(name);
        puts("READY");
        HANDLE first = accept_port(listener, 1);
        HANDLE second = accept_port(listener, 2);
        SetEvent(ready);
        if (queued) {
            await(proceed); // Client closed first before server reads its packet.
            int closed = 0;
            while (!closed) {
                NTSTATUS s = receive_raw(listener, &r);
                check(s, "drain abandoned connection");
                require(s != STATUS_TIMEOUT_VALUE && r.context == 1, "abandoned context");
                int type = r.message.head.type & 0xff;
                require(type == TYPE_CANCELLED || type == TYPE_CLOSED, "no abandoned data dispatch");
                closed = type == TYPE_CLOSED;
                release_message(listener, &r);
            }
            CloseHandle(first);
            first = NULL;
            SetEvent(finished);
        } else if (reverse) {
            HANDLE event = barrier(name, "returned-object");
            send_message(first, "return", 6, &event, 1);
            CloseHandle(event);
            expect_object(name, "returned-object", 1);
            SetEvent(proceed);
            await(finished); // Client closes its unread connection.
            expect_object(name, "returned-object", 0);
            CloseHandle(first);
            first = NULL;
        } else if (partial || rights) {
            check(receive_raw(listener, &r), "receive unimported handles");
            require((r.message.head.type & 0xff) == TYPE_DATAGRAM, "received test packet");
            import_handles(listener, &r, partial ? 1 : MAX_HANDLES);
            require(r.count == 1, "one handle adopted");
            if (rights) {
                require(r.count == 1, "reduced event received");
                SetLastError(0);
                require(!SetEvent(r.handles[0]) && GetLastError() == ERROR_ACCESS_DENIED,
                        "handle transfer preserves reduced rights");
                require(WaitForSingleObject(r.handles[0], 0) == WAIT_TIMEOUT,
                        "reduced event retains wait right");
            }
            release_message(listener, &r); // Includes any handle not imported.
            SetEvent(finished);
        } else {
            await(proceed);
        }
        pong(listener, second);
        await(done);
        if (first) CloseHandle(first);
        CloseHandle(second);
        CloseHandle(listener);
    } else {
        HANDLE first = connect_port(name), second = connect_port(name);
        await(ready);
        if (reverse) {
            await(proceed);
            CloseHandle(first);
            first = NULL;
            SetEvent(finished);
        } else if (!waitable) {
            HANDLE source[2] = {barrier(name, "object-0"), barrier(name, "object-1")};
            require(source[0] && source[1], "source objects");
            if (rights) {
                HANDLE reduced;
                require(DuplicateHandle(GetCurrentProcess(), source[0], GetCurrentProcess(),
                        &reduced, SYNCHRONIZE, FALSE, 0), "reduce own event rights");
                send_message(first, "rights", 6, &reduced, 1);
                CloseHandle(reduced);
            } else if (invalid) {
                HANDLE bad[2] = {source[0], NULL};
                require(try_send(first, "bad", 3, bad, 2) < 0, "partial send rejected");
                SetEvent(proceed);
            } else {
                send_message(first, "handles", 7, source, 2);
            }
            CloseHandle(source[0]);
            CloseHandle(source[1]);
            if (queued) {
                expect_object(name, "object-0", 1);
                expect_object(name, "object-1", 1);
                CloseHandle(first);
                first = NULL;
                // Observe cleanup BEFORE allowing the live server to receive.
                expect_object(name, "object-0", 0);
                expect_object(name, "object-1", 0);
                SetEvent(proceed);
            }
            if (!invalid) await(finished);
            expect_object(name, "object-0", 0);
            expect_object(name, "object-1", 0);
        } else {
            SetEvent(proceed);
        }
        ping(second);
        receive_data(second, &r);
        require(r.count == 0, "usable connection reply");
        release_message(second, &r);
        SetEvent(done);
        if (first) CloseHandle(first);
        CloseHandle(second);
    }
    CloseHandle(ready);
    CloseHandle(proceed);
    CloseHandle(finished);
    CloseHandle(done);
    printf("PASS %s %s\n", which, role);
    return 0;
}

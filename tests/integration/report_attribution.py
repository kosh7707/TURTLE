"""Independent checks for report record attribution and the server handshake window."""

ATTRIBUTION = "record_computation_attribution"
ATTRIBUTION_SCOPE = "primary_window_computation_segments"
SERVER_WINDOW = "server_client_hello_to_finished_send"
SERVER_WINDOW_DEFINITION = (
    "server_client_hello_receive_return_to_server_finished_send_return"
)

BOUNDARY_KEYS = {
    "kind",
    "boundary_event_sequence",
    "io_return_event_sequence",
    "record_indices",
    "names",
    "bundled",
    "mapping",
}
SEGMENT_KEYS = {
    "segment_index",
    "begin_event_sequence",
    "end_event_sequence",
    "elapsed_ns",
    "thread_cpu_ns",
    "thread_cpu_reason",
    "start",
    "end",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def event_map(rows, connection):
    return {
        event["sequence"]: event
        for event in rows[1:]
        if event.get("type") == "event" and event.get("connection") == connection
    }


def decoded_direction(decoded_connection, role, incoming):
    client_direction = (role == "client") != incoming
    return decoded_connection["client_sent" if client_direction else "server_sent"]


def names_for_records(direction, record_indices):
    selected = set(record_indices)
    return [
        message["name"]
        for message in direction["messages"]
        if selected.intersection(message["records"])
    ]


def records_are_bundled(direction, record_indices):
    """Bundling is about selected message instances, not a record's global flag."""
    selected = set(record_indices)
    instances = sum(
        1 for message in direction["messages"]
        if selected.intersection(message["records"])
    )
    return instances > 1


def records_completed_by(direction, event):
    begin, end = event["stream_begin"], event["stream_end"]
    return [
        record["index"]
        for record in direction["records"]
        if begin < record["stream_end"] <= end
    ]


def records_touched_by(direction, event):
    begin, end = event["stream_begin"], event["stream_end"]
    return [
        record["index"]
        for record in direction["records"]
        if record["stream_begin"] < end and record["stream_end"] > begin
    ]


def validate_boundary(boundary, position, events, decoded_connection, role, context):
    require(set(boundary) == BOUNDARY_KEYS, f"{context}: malformed {position} boundary")
    event = events.get(boundary["boundary_event_sequence"])
    require(event is not None, f"{context}: boundary refers to an absent raw event")
    kind = boundary["kind"]
    if kind in ("call_begin", "call_end"):
        expected = "CALL_BEGIN" if kind == "call_begin" else "CALL_END"
        require(event["kind"] == expected, f"{context}: {kind} points to {event['kind']}")
        require(boundary["io_return_event_sequence"] is None,
                f"{context}: call boundary fabricated an I/O return")
        require(boundary["record_indices"] == [] and boundary["names"] == [] and
                boundary["bundled"] is False and boundary["mapping"] == "boundary_event",
                f"{context}: call boundary fabricated record attribution")
        return

    require(kind in ("after_receive", "before_send"),
            f"{context}: unknown attribution boundary {kind}")
    return_event = events.get(boundary["io_return_event_sequence"])
    require(return_event is not None and return_event.get("result") == 0 and
            return_event.get("transferred", 0) > 0,
            f"{context}: record attribution lacks a successful nonempty I/O return")
    require(return_event.get("stream_end") - return_event.get("stream_begin") ==
            return_event.get("transferred"),
            f"{context}: I/O return stream range differs from actual transferred bytes")
    if kind == "after_receive":
        require(event["kind"] == "IO_RECV_RETURN" and event is return_event,
                f"{context}: after_receive does not point to its receive return")
        direction = decoded_direction(decoded_connection, role, incoming=True)
        expected_records = records_completed_by(direction, return_event)
    else:
        require(event["kind"] == "IO_SEND_ENTER" and
                return_event["kind"] == "IO_SEND_RETURN" and
                event["sequence"] < return_event["sequence"] and
                event["call_id"] == return_event["call_id"] and
                event["connection"] == return_event["connection"],
                f"{context}: before_send enter/return pair is not the same call")
        direction = decoded_direction(decoded_connection, role, incoming=False)
        expected_records = records_touched_by(direction, return_event)
    expected_names = names_for_records(direction, expected_records)
    require(expected_records and boundary["record_indices"] == expected_records,
            f"{context}: {kind} record indices do not match actual returned bytes")
    require(boundary["names"] == expected_names and
            boundary["bundled"] is records_are_bundled(direction, expected_records) and
            boundary["mapping"] == "record_envelope",
            f"{context}: {kind} names or bundling differ from decoded records")


def matching_successful_send(events, enter):
    for event in sorted(events.values(), key=lambda item: item["sequence"]):
        if event["sequence"] <= enter["sequence"]:
            continue
        if event["kind"] == "IO_SEND_ENTER":
            return None
        if event["kind"] != "IO_SEND_RETURN":
            continue
        if event["connection"] != enter["connection"] or event["call_id"] != enter["call_id"]:
            return None
        successful = (
            event.get("result") == 0 and event.get("transferred", 0) > 0 and
            event.get("stream_end", 0) > event.get("stream_begin", 0)
        )
        if successful:
            return event
        return None
    return None


def expected_boundary(position, event, events, decoded_connection, role):
    if position == "start":
        if event["kind"] == "CALL_BEGIN":
            return "call_begin"
        if event["kind"] == "IO_RECV_RETURN":
            direction = decoded_direction(decoded_connection, role, incoming=True)
            if records_completed_by(direction, event):
                return "after_receive"
        return None
    if event["kind"] == "CALL_END":
        return "call_end"
    if event["kind"] == "IO_SEND_ENTER":
        returned = matching_successful_send(events, event)
        if returned is not None:
            direction = decoded_direction(decoded_connection, role, incoming=False)
            if records_touched_by(direction, returned):
                return "before_send"
    return None


def validate_available_attribution(connection, rows, decoded_connection, role, context):
    attribution = connection.get(ATTRIBUTION)
    require(isinstance(attribution, dict) and attribution.get("available") is True and
            attribution.get("reason") is None and
            attribution.get("scope") == ATTRIBUTION_SCOPE and
            isinstance(attribution.get("segments"), list),
            f"{context}: record computation attribution is unavailable or malformed")
    segments = attribution["segments"]
    computation = [
        (index, segment)
        for index, segment in enumerate(connection["segments"])
        if segment["kind"] == "computation"
    ]
    require(len(segments) == len(computation) and segments,
            f"{context}: attribution did not preserve every computation segment")
    events = event_map(rows, connection["connection"])
    observed_indices = []
    for attributed, (index, original) in zip(segments, computation):
        require(set(attributed) == SEGMENT_KEYS,
                f"{context}: malformed attributed computation segment")
        require(attributed["segment_index"] == index,
                f"{context}: computation segment index changed")
        begin = events.get(attributed["begin_event_sequence"])
        end = events.get(attributed["end_event_sequence"])
        require(begin is not None and end is not None and begin["sequence"] < end["sequence"],
                f"{context}: computation segment raw boundaries are absent or reversed")
        elapsed = end["monotonic_ns"] - begin["monotonic_ns"]
        require(attributed["elapsed_ns"] == elapsed == original["elapsed_ns"],
                f"{context}: computation elapsed time was changed or duplicated")
        begin_cpu, end_cpu = begin.get("thread_cpu_ns"), end.get("thread_cpu_ns")
        if isinstance(begin_cpu, int) and isinstance(end_cpu, int):
            require(attributed["thread_cpu_ns"] == end_cpu - begin_cpu and
                    attributed["thread_cpu_reason"] is None,
                    f"{context}: computation CPU difference was not raw-recomputed")
        else:
            require(attributed["thread_cpu_ns"] is None and
                    isinstance(attributed["thread_cpu_reason"], str),
                    f"{context}: unavailable computation CPU was reported as zero")
        for position in ("start", "end"):
            boundary = attributed[position]
            boundary_event = begin if position == "start" else end
            expected_kind = expected_boundary(
                position, boundary_event, events, decoded_connection, role
            )
            require((boundary is None) == (expected_kind is None),
                    f"{context}: expected {position} attribution was omitted or fabricated")
            if boundary is not None:
                require(boundary["kind"] == expected_kind,
                        f"{context}: {position} attribution has the wrong boundary kind")
                validate_boundary(boundary, position, events, decoded_connection, role, context)
        observed_indices.append(index)
    require(len(observed_indices) == len(set(observed_indices)) and
            sum(segment["elapsed_ns"] for segment in segments) == connection["computation_ns"],
            f"{context}: computation segments were duplicated or omitted")
    return attribution


def validate_unavailable_attribution(connection, reason, context):
    attribution = connection.get(ATTRIBUTION)
    require(attribution == {
        "available": False,
        "reason": reason,
        "scope": ATTRIBUTION_SCOPE,
        "segments": None,
    }, f"{context}: unavailable record attribution was fabricated or lost its reason")


def record_range(direction, message_name):
    messages = [message for message in direction["messages"] if message["name"] == message_name]
    require(len(messages) == 1, f"expected exactly one decoded {message_name}")
    ranges = messages[0]["record_stream_ranges"]
    require(ranges, f"decoded {message_name} has no record range")
    return min(item["begin"] for item in ranges), max(item["end"] for item in ranges)


def first_return_covering(events, kind, offset, completion):
    matches = [
        event
        for event in events.values()
        if event.get("kind") == kind and event.get("result") == 0 and
        event.get("transferred", 0) > 0 and
        ((event["stream_begin"] <= offset < event["stream_end"])
         if not completion else
         (event["stream_begin"] < offset <= event["stream_end"]))
    ]
    require(matches, f"no successful {kind} return covers decoded record boundary {offset}")
    return min(matches, key=lambda event: event["sequence"])


def validate_server_window(connection, rows, decoded_connection, context):
    window = connection.get(SERVER_WINDOW)
    require(isinstance(window, dict) and window.get("available") is True and
            window.get("reason") is None and
            window.get("definition") == SERVER_WINDOW_DEFINITION,
            f"{context}: server ClientHello-to-Finished window is unavailable or malformed")
    events = event_map(rows, connection["connection"])
    client_hello_begin, _ = record_range(decoded_connection["client_sent"], "ClientHello")
    _, finished_end = record_range(decoded_connection["server_sent"], "Finished")
    start = first_return_covering(events, "IO_RECV_RETURN", client_hello_begin, False)
    end = first_return_covering(events, "IO_SEND_RETURN", finished_end, True)
    require(window["start_event_sequence"] == start["sequence"] and
            window["end_event_sequence"] == end["sequence"] and
            window["elapsed_ns"] == end["monotonic_ns"] - start["monotonic_ns"],
            f"{context}: server window does not match raw record-envelope returns")
    start_cpu, end_cpu = start.get("thread_cpu_ns"), end.get("thread_cpu_ns")
    if isinstance(start_cpu, int) and isinstance(end_cpu, int):
        require(window["thread_cpu_ns"] == end_cpu - start_cpu and
                window["thread_cpu_reason"] is None,
                f"{context}: server window CPU value was not raw-recomputed")
    else:
        require(window["thread_cpu_ns"] is None and
                isinstance(window["thread_cpu_reason"], str),
                f"{context}: unavailable server-window CPU was reported as zero")
    application_sends = [
        event for event in events.values()
        if event.get("kind") == "IO_SEND_RETURN" and event.get("call") == "app_send" and
        event.get("result") == 0 and event.get("transferred", 0) > 0
    ]
    require(end["call"] == "handshake" and application_sends and
            all(event["sequence"] > end["sequence"] for event in application_sends),
            f"{context}: server window includes application send bytes")
    return window


def validate_unavailable_server_window(connection, reason, context):
    window = connection.get(SERVER_WINDOW)
    require(isinstance(window, dict) and window.get("available") is False and
            window.get("reason") == reason and
            window.get("definition") == SERVER_WINDOW_DEFINITION,
            f"{context}: unavailable server window lost its reason or definition")
    for field in ("start_event_sequence", "end_event_sequence", "elapsed_ns",
                  "thread_cpu_ns", "cycles"):
        require(window.get(field) is None,
                f"{context}: unavailable server window fabricated {field}")
    require(window.get("thread_cpu_reason") == reason,
            f"{context}: unavailable server window CPU reason differs from its boundary reason")


def validate_no_attribution_metrics(groups):
    forbidden = (ATTRIBUTION, "after_receive", "before_send")
    for group in groups:
        metrics = group.get("metrics", {})
        require(not any(any(marker in name for marker in forbidden) for name in metrics),
                "record-attribution segment entered automatic metric aggregation")

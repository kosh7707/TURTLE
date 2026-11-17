-- 개발 검증용 Decode As 해석기. 원본 pcap과 TLS 바이트를 변경하지 않는다.
-- 프레임 길이: TU(2) + 방향별 번호(2) + TLS 헤더(5) + TLS 페이로드.
local turtle = Proto("turtle", "TURTLE record framing")
local f = {
    magic = ProtoField.string("turtle.magic", "Magic"),
    number = ProtoField.uint16("turtle.record_number", "Record number", base.DEC),
    kind = ProtoField.uint8("turtle.tls_type", "TLS outer content type", base.DEC),
    version = ProtoField.uint16("turtle.tls_version", "TLS legacy record version", base.HEX),
    length = ProtoField.uint16("turtle.tls_length", "TLS payload length", base.DEC),
    record = ProtoField.bytes("turtle.tls_record", "Original TLS record"),
}
turtle.fields = f
local invalid = ProtoExpert.new("turtle.invalid_frame", "Invalid TURTLE frame",
    expert.group.MALFORMED, expert.severity.ERROR)
turtle.experts = {invalid}
local tls = Dissector.get("tls")

local function pdu_length(tvb, pinfo, offset)
    return 9 + tvb(offset + 7, 2):uint()
end

local function dissect_record(tvb, pinfo, tree)
    local node = tree:add(turtle, tvb(), "TURTLE record #" .. tvb(2, 2):uint())
    node:add(f.magic, tvb(0, 2))
    node:add(f.number, tvb(2, 2))
    node:add(f.kind, tvb(4, 1))
    node:add(f.version, tvb(5, 2))
    node:add(f.length, tvb(7, 2))
    node:add(f.record, tvb(4))
    if tvb(0, 2):string() ~= "TU" or tvb(2, 2):uint() == 0 then
        node:add_proto_expert_info(invalid)
        return tvb:len()
    end
    -- TLS 자체의 Hello/레코드 트리를 사용한다. 암호화 내용은 복호화하지 않는다.
    -- TLS 해석기가 기록한 내용을 보존하고 패킷 목록의 프로토콜만 구분한다.
    tls:call(tvb(4):tvb(), pinfo, tree)
    pinfo.cols.protocol = "TURTLE/TLS"
    return tvb:len()
end

function turtle.dissector(tvb, pinfo, tree)
    dissect_tcp_pdus(tvb, tree, 9, pdu_length, dissect_record, true)
end

-- 실험마다 달라지는 서버 포트를 사용자가 명시적으로 선택한다.
DissectorTable.get("tcp.port"):add_for_decode_as(turtle)

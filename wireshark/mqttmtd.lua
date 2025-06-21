--[[
  MQTT MTD Auth Server Packet Dissector for Wireshark
  Version: 2.0
  Author: Kentaro Kusumi

  This dissector identifies packets based on the TCP port 18771 (Issuer) and 22085 (Verifier).
  It supports dissection of Auth Server Issuer and Verifier requests and responses,
  including conversation tracking to attempt full Issuer Response dissection.
--]]

local mqttmtd_proto = Proto("mqttmtd", "MQTT-MTD Auth Server Protocol")

-- AEAD Algorithm Enum
local aead_algo_vals = {
    [0x1] = "AES_128_GCM",
    [0x2] = "AES_256_GCM",
    [0x3] = "CHACHA20_POLY1305"
}

-- IsPub bit
local is_pub_tbl = {[0x0] = "Subscribe", [0x1] = "Publish"}

-- Common Header Fields
local MQTTMTD_HDR_LEN = 1
local abbr_hdr = "mqttmtd.header."
local pf_hdr_compound = ProtoField.uint8(abbr_hdr .. "compound"       , "Header", base.HEX)
local pf_hdr_version  = ProtoField.uint8(abbr_hdr .. "mqttmtd_version", "MQTT-MTD version"    , base.DEC)
local packet_type_vals = {
    [0x0] = "Issuer Request",
    [0x1] = "Issuer Response",
    [0x4] = "Verifier Request",
    [0x5] = "Verifier Response"
}
local pf_hdr_packet_type = ProtoField.uint8(abbr_hdr .. "packet_type", "Packet Type", base.HEX, packet_type_vals)

local TIMESTAMP_LEN = 6
local RANDOM_LEN = 6
local TOKEN_LEN = 12

-- Issuer Request Fields
local abbr_is_req = "mqttmtd.issuer.request."
local pf_is_req_compound        = ProtoField.uint8 (abbr_is_req .. "compound"       , "Compound byte", base.HEX)
local pf_is_req_is_pub          = ProtoField.uint8 (abbr_is_req .. "is_pub"         , "Type", base.HEX, is_pub_tbl)
local pf_is_req_num_tokens_div4 = ProtoField.uint8 (abbr_is_req .. "num_tokens_div4", "Number of tokens divided by 4", base.DEC)
local pf_is_req_aead_algo       = ProtoField.uint8 (abbr_is_req .. "aead_algo"      , "AEAD algorithm", base.HEX, aead_algo_vals)
local pf_is_req_topic_len       = ProtoField.uint16(abbr_is_req .. "topic_len"      , "Topic length", base.DEC)
local pf_is_req_topic           = ProtoField.string(abbr_is_req .. "topic"          , "Topic", base.UNICODE)


-- Issuer Response Fields
local abbr_is_resp = "mqttmtd.issuer.response."
local pf_is_resp_status_vals = {
    [0x01] = "Success",
    [0xFF] = "Error"
}
local pf_is_resp_status      = ProtoField.uint8 (abbr_is_req .. "status"     , "Status", base.HEX, pf_is_resp_status_vals)
local pf_is_resp_secret_key     = ProtoField.bytes (abbr_is_req .. "secret_key"    , "Secret key")
local pf_is_resp_nonce_base  = ProtoField.bytes (abbr_is_req .. "nonce_base" , "Nonce base")
local pf_is_resp_timestamp   = ProtoField.bytes (abbr_is_req .. "timestamp"  , "Timestamp")

-- Verifier Request Fields
local abbr_ve_req = "mqttmtd.verifier.request."
local pf_ve_req_token = ProtoField.bytes(abbr_ve_req .. "token", "Token")
local pf_ve_req_token_timestamp = ProtoField.bytes(abbr_ve_req .. "token.timestamp", "Timestamp")
local pf_ve_req_token_random = ProtoField.bytes(abbr_ve_req .. "token.random", "Random")

-- Verifier Response Fields
local abbr_ve_resp = "mqttmtd.verifier.response."
local pf_ve_resp_status_vals = {
    [0x01] = "Success",
    [0x02] = "Failure",
    [0xFF] = "Error"
}
local pf_ve_resp_status    = ProtoField.uint8 (abbr_ve_resp .. "status"   , "Status", base.HEX, pf_ve_resp_status_vals)
local pf_ve_resp_compound  = ProtoField.uint8 (abbr_ve_resp .. "compound" , "Compound byte", base.HEX)
local pf_ve_resp_is_pub    = ProtoField.uint8  (abbr_ve_resp .. "is_pub"   , "Token for", base.HEX, is_pub_tbl)
local pf_ve_resp_aead_algo = ProtoField.uint8 (abbr_ve_resp .. "aead_algo", "AEAD algorithm", base.HEX, aead_algo_vals)
local pf_ve_resp_topic_len = ProtoField.uint16(abbr_ve_resp .. "topic_len", "Topic length", base.DEC)
local pf_ve_resp_topic     = ProtoField.string(abbr_ve_resp .. "topic"    , "Topic", base.UNICODE)
local pf_ve_resp_secret_key   = ProtoField.bytes (abbr_ve_resp .. "secret_key"  , "Secret key")
local pf_ve_resp_nonce     = ProtoField.bytes (abbr_ve_resp .. "nonce"    , "Nonce")

mqttmtd_proto.fields = {
    pf_hdr_compound,
        pf_hdr_version,
        pf_hdr_packet_type,

    pf_is_req_compound,
        pf_is_req_is_pub,
        pf_is_req_num_tokens_div4,
    pf_is_req_aead_algo,
    pf_is_req_topic_len,
    pf_is_req_topic,

    pf_is_resp_status,
    pf_is_resp_secret_key,
    pf_is_resp_nonce_base,
    pf_is_resp_timestamp,

    pf_ve_req_token,
        pf_ve_req_token_timestamp,
        pf_ve_req_token_random,

    pf_ve_resp_status,
    pf_ve_resp_compound,
        pf_ve_resp_is_pub,
        pf_ve_resp_aead_algo,
    pf_ve_resp_topic_len,
    pf_ve_resp_topic,
    pf_ve_resp_secret_key,
    pf_ve_resp_nonce
}


-- Helper function to determine AEAD key length
local function get_aead_key_length(aead_id)
    if aead_id == 1 then
        return 16                      -- AES_128_GCM
    elseif aead_id == 2 then
        return 32                      -- AES_256_GCM
    elseif aead_id == 3 then
        return 32                      -- CHACHA20_POLY1305
    end
    return nil                         -- Unknown or invalid AEAD ID
end

-- Helper function to determine AEAD nonce length
local function get_aead_nonce_length(aead_id)
    if aead_id == 1 then
        return 12                      -- AES_128_GCM
    elseif aead_id == 2 then
        return 12                      -- AES_256_GCM
    elseif aead_id == 3 then
        return 12                      -- CHACHA20_POLY1305
    end
    return nil                         -- Unknown or invalid AEAD ID
end


local BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
function base64_encode_tvbrange(tvb_range)
    if not tvb_range then
        return ""
    end

    local len = tvb_range:len()
    if len == 0 then
        return ""
    end

    local output = {}
    local output_idx = 1
    local i = 0

    while i < len do
        -- 3バイトを読み込む
        local byte1 = tvb_range(i, 1):uint()
        local byte2 = 0
        local byte3 = 0
        local num_bytes = 1

        if i + 1 < len then
            byte2 = tvb_range(i + 1, 1):uint()
            num_bytes = num_bytes + 1
        end
        if i + 2 < len then
            byte3 = tvb_range(i + 2, 1):uint()
            num_bytes = num_bytes + 1
        end

        -- 6ビットごとに分割し、Base64文字に変換
        -- 1バイト目 (8ビット): c1 (6ビット), c2_part (2ビット)
        output[output_idx] = BASE64_CHARS:sub((byte1 >> 2) + 1, (byte1 >> 2) + 1)
        output_idx = output_idx + 1

        -- 2バイト目 (8ビット): c2_part (4ビット), c3_part (4ビット)
        output[output_idx] = BASE64_CHARS:sub(((byte1 & 0x03) << 4 | (byte2 >> 4)) + 1, ((byte1 & 0x03) << 4 | (byte2 >> 4)) + 1)
        output_idx = output_idx + 1

        -- 3バイト目 (8ビット): c3_part (2ビット), c4 (6ビット)
        -- パディングを考慮
        if num_bytes > 1 then
            output[output_idx] = BASE64_CHARS:sub(((byte2 & 0x0F) << 2 | (byte3 >> 6)) + 1, ((byte2 & 0x0F) << 2 | (byte3 >> 6)) + 1)
            output_idx = output_idx + 1
        end

        if num_bytes > 2 then
            output[output_idx] = BASE64_CHARS:sub((byte3 & 0x3F) + 1, (byte3 & 0x3F) + 1)
            output_idx = output_idx + 1
        end

        i = i + 3
    end

    return table.concat(output)
end

-- 現在のTCPストリームの識別子を取得する
local tcp_stream_id_field = Field.new("tcp.stream")
-- TCPストリームごとにリクエスト情報を保存するためのグローバルテーブル
-- キーは tcp.stream インデックス、値はそのストリームのリクエスト情報（テーブル）
local stream_requests = {}

function mqttmtd_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length < MQTTMTD_HDR_LEN then return end

    pinfo.cols.protocol = mqttmtd_proto.name

    local subtree = tree:add(mqttmtd_proto, buffer(), "MQTT-MTD Auth Server Protocol Data")

--     Header
    local version = buffer(0, 1):bitfield(0, 4)
    local packet_type = buffer(0, 1):bitfield(4, 4)
    if packet_type_vals[packet_type] == nil then return end
    local tree_hdr = subtree:add(pf_hdr_compound, buffer(0, 1)):append_text(" (MQTT-MTD v" .. version .. ", " .. packet_type_vals[packet_type] ..")")
    tree_hdr:add(pf_hdr_version, version)
    tree_hdr:add(pf_hdr_packet_type, packet_type)

    pinfo.cols.protocol = mqttmtd_proto.name .. "v" .. version
    pinfo.cols.info = packet_type_vals[packet_type]

--     Payload
    if packet_type == 0x0 then
        -- Issuer Request
        bytes_consumed = handler_issuer_request(buffer, pinfo, subtree)
    elseif packet_type == 0x1 then
        -- Issuer Response
        bytes_consumed = handler_issuer_response(buffer, pinfo, subtree)
    elseif packet_type == 0x4 then
        -- Verifier Request
        bytes_consumed = handler_verifier_request(buffer, pinfo, subtree)
    else
        -- Verifier Response
        bytes_consumed = handler_verifier_response(buffer, pinfo, subtree)
    end

    return bytes_consumed
end

function handler_issuer_request(buffer, pinfo, subtree)
    local offset = 1

    local compound = buffer(offset, 1)
    offset = offset + 1
    local is_pub = compound:bitfield(0, 1)
    local num_tokens_div4 = compound:bitfield(1, 7)
    local tree_compound = subtree:add(pf_hdr_compound, compound):append_text(" (" .. is_pub_tbl[is_pub] .. ", " .. (num_tokens_div4 * 4) .." tokens)")
    tree_compound:add(pf_is_req_is_pub, is_pub)
    tree_compound:add(pf_is_req_num_tokens_div4, num_tokens_div4)

    local algo = buffer(offset, 1)
    offset = offset + 1
    subtree:add(pf_is_req_aead_algo, algo)

    local topic_len = buffer(offset, 2)
    offset = offset + 2
    local topic = buffer(offset, topic_len:uint())
    offset = offset + topic_len:uint()
    subtree:add(pf_is_req_topic_len, topic_len)
    subtree:add(pf_is_req_topic, topic)
    pinfo.cols.info = "Issuer Request [" .. is_pub_tbl[is_pub] .. ", " .. (num_tokens_div4 * 4) .. " tokens, " .. aead_algo_vals[algo:uint()] .. ", " .. topic:string() .. "]"

    -- 現在のTCPストリームの識別子を取得
    local tcp_stream_id = tcp_stream_id_field().value

    -- このストリームのリクエスト情報を保存するエントリを作成
    stream_requests[tcp_stream_id] = {
         algo = algo:uint(),
     }
    print("Request ".. tcp_stream_id .. ", ".. stream_requests[tcp_stream_id].algo)

    return offset
end

function handler_issuer_response(buffer, pinfo, subtree)
    local offset = 1

    local status = buffer(offset, 1)
    offset = offset + 1
    subtree:add(pf_is_resp_status, status)
    pinfo.cols.info = "Issuer Response (" ..  pf_is_resp_status_vals[status:uint()] .. ")"
    if status:uint() ~= 1 then return end

    -- 現在のTCPストリームの識別子を取得
    local tcp_stream_id = tcp_stream_id_field().value

    -- このストリームのリクエスト情報を保存するテーブルを検索
    if not stream_requests[tcp_stream_id] then return end
    local algo = stream_requests[tcp_stream_id].algo

    local key_len = get_aead_key_length(algo)
    if key_len == nil then return offset end
    local session_key = buffer(offset, key_len)
    offset = offset + key_len
    subtree:add(pf_is_resp_secret_key, session_key)

    local nonce_len = get_aead_nonce_length(algo)
    if nonce_len == nil then return offset end
    local nonce_base = buffer(offset, nonce_len)
    offset = offset + nonce_len
    subtree:add(pf_is_resp_nonce_base, nonce_base)

    local timestamp = buffer(offset, TIMESTAMP_LEN)
    offset = offset + TIMESTAMP_LEN
    subtree:add(pf_is_resp_timestamp, timestamp)

    pinfo.cols.info = "Issuer Response (" ..  pf_is_resp_status_vals[status:uint()] .. ") [".. base64_encode_tvbrange(timestamp) .."]"

    -- エントリを削除
    stream_requests[tcp_stream_id] = nil

    return offset
end

function handler_verifier_request(buffer, pinfo, subtree)
    local tree_token = subtree:add(pf_ve_req_token, buffer(1, TOKEN_LEN))
    tree_token:add(pf_ve_req_token_timestamp,buffer(1, TIMESTAMP_LEN) )
    tree_token:add(pf_ve_req_token_random,buffer(1+TIMESTAMP_LEN, RANDOM_LEN))
    local token_encoded = base64_encode_tvbrange(buffer(1, TOKEN_LEN))
    pinfo.cols.info = "Verifier Request [" ..  token_encoded .. "]"
    return 1 + TOKEN_LEN
end

function handler_verifier_response(buffer, pinfo, subtree)
    local offset = 1

    local status = buffer(offset, 1)
    offset = offset + 1
    subtree:add(pf_ve_resp_status, status)
    pinfo.cols.info = "Verifier Response (" ..  pf_ve_resp_status_vals[status:uint()] .. ")"
    if status:uint() ~= 1 then return end

    local compound = buffer(offset, 1)
    offset = offset + 1
    local is_pub = compound:bitfield(0, 1)
    local algo = compound:bitfield(4, 4)
    local tree_compound = subtree:add(pf_ve_resp_compound, compound):append_text(" (" .. is_pub_tbl[is_pub] .. ", " .. aead_algo_vals[algo] .. ")")
    tree_compound:add(pf_ve_resp_is_pub, is_pub)
    tree_compound:add(pf_ve_resp_aead_algo, algo)
    pinfo.cols.info = "Verifier Response (" ..  pf_ve_resp_status_vals[status:uint()] .. ") [" .. is_pub_tbl[is_pub] .. ", " .. aead_algo_vals[algo] .. "]"

    local topic_len = buffer(offset, 2)
    offset = offset + 2
    local topic = buffer(offset, topic_len:uint())
    offset = offset + topic_len:uint()
    subtree:add(pf_ve_resp_topic_len, topic_len)
    subtree:add(pf_ve_resp_topic, topic)
    pinfo.cols.info = "Verifier Response (" ..  pf_ve_resp_status_vals[status:uint()] .. ") [" .. is_pub_tbl[is_pub] .. ", " .. aead_algo_vals[algo] .. ", " .. topic:string() .. "]"

    local key_len = get_aead_key_length(algo)
    if key_len == nil then return offset end
    local session_key = buffer(offset, key_len)
    offset = offset + key_len
    subtree:add(pf_ve_resp_secret_key, session_key)

    local nonce_len = get_aead_nonce_length(algo)
    if nonce_len == nil then return offset end
    local nonce = buffer(offset, nonce_len)
    offset = offset + nonce_len
    subtree:add(pf_ve_resp_nonce, nonce)
    return offset
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(22085, mqttmtd_proto)
local tls_port = DissectorTable.get("tls.port")
tls_port:add(18771, mqttmtd_proto)
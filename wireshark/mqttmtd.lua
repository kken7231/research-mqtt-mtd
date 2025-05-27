--[[
  Auth Server Packet Dissector for Wireshark
  Version: 1.0
  Author: Your Name/AI Assistant

  This dissector identifies packets based on the magic number 0x4D51ED.
  It supports dissection of Issuer and Verifier requests and responses,
  including conversation tracking to attempt full Issuer Response dissection.

  Known limitations:
  - Issuer Response dissection relies on information from a preceding Issuer Request
    within the same conversation. If the request is not present or the conversation
    tracking assumptions do not hold (e.g., out-of-order packets not handled by TCP,
    multiple interleaved request/response pairs without unique IDs), dissection
    of some Issuer Response fields may be incomplete.
--]]

-- 1. Protocol Definition
local auth_server_proto = Proto("auth_server", "Auth Server Protocol")

-- 2. Protocol Fields

-- Common Header Fields
local pf_header_compound = ProtoField.uint8("auth_server.header.compound", "Header Compound Byte", base.HEX)
local pf_header_version = ProtoField.uint8("auth_server.header.version", "MQTT-MTD Version", base.DEC)
local packet_type_vals = {
    [0x0] = "Issuer Request",
    [0x1] = "Issuer Response",
    [0x4] = "Verifier Request",
    [0x5] = "Verifier Response"
}
local pf_header_packet_type = ProtoField.uint8("auth_server.header.packet_type", "Packet Type", base.HEX,
    packet_type_vals)

-- AEAD Algorithm Enum
local aead_algs_vals = {
    [0] = "AES_128_GCM (16-byte key)",
    [1] = "AES_256_GCM (32-byte key)",
    [2] = "CHACHA20_POLY1305 (32-byte key)"
}
local pf_aead_algorithm = ProtoField.uint8("auth_server.aead_algorithm", "AEAD Algorithm", base.DEC, aead_algs_vals)

-- Topic Fields
local pf_topic_length = ProtoField.uint16("auth_server.topic.length", "Topic Length", base.DEC)
local pf_topic_name = ProtoField.string("auth_server.topic.name", "Topic Name") -- UTF-8 encoded

-- Issuer Request Fields
local pf_issuer_req_compound = ProtoField.uint8("auth_server.issuer.request.compound", "Issuer Request Compound Byte",
    base.HEX)
local pf_issuer_req_is_pub = ProtoField.bool("auth_server.issuer.request.is_pub", "Request for Pub Tokens", 8,
    { "Requests for Sub Tokens", "Requests for Pub Tokens" }, 0x80)                                                                                                          -- Mask for bit 7
local pf_issuer_req_num_tokens_div4 = ProtoField.uint8("auth_server.issuer.request.num_tokens_div4",
    "Requested number of tokens / 4", base.DEC, nil, 0x7F)                                                                                                                   -- Mask for bits 6-0

-- Issuer Response Fields
local pf_issuer_resp_status_vals = {
    [0x01] = "Success",
    [0xFF] = "Error"
}
local pf_issuer_resp_status = ProtoField.uint8("auth_server.issuer.response.status", "Status", base.HEX,
    pf_issuer_resp_status_vals)
local pf_issuer_resp_key = ProtoField.bytes("auth_server.issuer.response.key", "Encryption Key")
local pf_issuer_resp_nonce_base = ProtoField.bytes("auth_server.issuer.response.nonce_base", "Nonce Base (12 bytes)",
    base.NONE)
local pf_issuer_resp_timestamp = ProtoField.bytes("auth_server.issuer.response.timestamp", "Timestamp (6 bytes)",
    base.NONE)
local pf_issuer_resp_all_randoms = ProtoField.bytes("auth_server.issuer.response.all_randoms",
    "All Randoms (concatenated)")
local pf_issuer_resp_info_source = ProtoField.string("auth_server.issuer.response.info_source",
    "Info Source for Key/Randoms dissection")
local pf_issuer_resp_undissected_payload = ProtoField.bytes("auth_server.issuer.response.undissected_payload",
    "Undissected Success Payload (req info missing)")


-- Verifier Request Fields
local pf_verifier_req_token = ProtoField.bytes("auth_server.verifier.request.token", "Token (12 bytes)", base.NONE)

-- Verifier Response Fields
local pf_verifier_resp_status_vals = {
    [0x01] = "Success",
    [0x02] = "Failure",
    [0xFF] = "Error"
}
local pf_verifier_resp_status = ProtoField.uint8("auth_server.verifier.response.status", "Status", base.HEX,
    pf_verifier_resp_status_vals)
local pf_verifier_resp_compound = ProtoField.uint8("auth_server.verifier.response.compound",
    "Verifier Response Compound Byte", base.HEX)
local pf_verifier_resp_is_pub = ProtoField.bool("auth_server.verifier.response.is_pub", "Allowed Access Type", 8,
    { "Sub Verified", "Pub Verified" }, 0x80)                                                                                                             -- Mask for bit 7
local pf_verifier_resp_aead_algo = ProtoField.uint8("auth_server.verifier.response.aead_algorithm", "AEAD Algorithm",
    base.DEC, aead_algs_vals, 0x7F)                                                                                                                       -- Mask for bits 6-0
local pf_verifier_resp_key = ProtoField.bytes("auth_server.verifier.response.key", "Encryption Key")
local pf_verifier_resp_nonce = ProtoField.bytes("auth_server.verifier.response.nonce", "Nonce (12 bytes)", base.NONE)


-- Register all fields with the protocol
auth_server_proto.fields = {
    pf_header_compound,
    pf_header_version,
    pf_header_packet_type,
    pf_aead_algorithm,
    pf_topic_length,
    pf_topic_name,
    pf_issuer_req_compound,
    pf_issuer_req_is_pub,
    pf_issuer_req_num_tokens_div4,
    pf_issuer_resp_status,
    pf_issuer_resp_key,
    pf_issuer_resp_nonce_base,
    pf_issuer_resp_timestamp,
    pf_issuer_resp_all_randoms,
    pf_issuer_resp_info_source,
    pf_issuer_resp_undissected_payload,
    pf_verifier_req_token,
    pf_verifier_resp_status,
    pf_verifier_resp_compound,
    pf_verifier_resp_is_pub,
    pf_verifier_resp_aead_algo,
    pf_verifier_resp_key,
    pf_verifier_resp_nonce
}

-- Helper function to determine AEAD key length
local function get_aead_key_length(aead_id)
    if aead_id == 0 then
        return 16                      -- AES_128_GCM
    elseif aead_id == 1 then
        return 32                      -- AES_256_GCM
    elseif aead_id == 2 then
        return 32                      -- CHACHA20_POLY1305
    end
    return nil                         -- Unknown or invalid AEAD ID
end

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

local DEBUG = debug_level.LEVEL_1

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end

local MQTTMTD_HDR_LEN = 1

local ef_too_short = ProtoExpert.new("mqttmtd.too_short.expert", "MQTT-MTD packet too short",
                                     expert.group.MALFORMED, expert.severity.ERROR)

-- 3. Main Dissector Function
function mqttmtd.dissector(tvbuf, pktinfo, root)
    dprint2("mqttmtd.dissector called")

    -- set the protocol column
    pktinfo.cols.protocol:set("MQTT-MTD")

    local pktlen = tvbuf:report_length_remaining()
    local offset = 0
    local tree = root:add(mqttmtd, tvbuf:range(0, pktlen))

    if pktlen < MQTTMTD_HDR_LEN then
        tree:add_proto_expert_info(ef_too_short)
        dprint("packet length", pktlen, "too short")
        return
    end

    local headerrange = tvbuf:range(offset, 1)
    local header_tree = tree:add(pf_header_compound, headerrange)
        header_compound_subtree:add(pf_header_version, headerrange, mqtt_mtd_version)
        header_compound_subtree:add(pf_header_packet_type, headerrange, packet_type)
    offset = offset + 1


    tree:add(pf_)


    local pkt_len = tvbuf:len()
    local offset = 0

    pinfo.cols.protocol = auth_server_proto.name
    local subtree = tree:add(auth_server_proto, buffer(), "Auth Server Protocol Data (Magic: 0x4D51ED)")

    -- Compound Byte for Header
    if pkt_len < offset + 1 then
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Header Compound Byte"); return offset
    end
    local header_compound_byte = buffer(offset, 1):uint()
    local header_compound_subtree = subtree:add(pf_header_compound, buffer(offset, 1))
    local mqtt_mtd_version = (header_compound_byte >> 4) & 0x0F
    local packet_type = header_compound_byte & 0x0F
    header_compound_subtree:add(pf_header_version, buffer(offset, 1), mqtt_mtd_version)
    header_compound_subtree:add(pf_header_packet_type, buffer(offset, 1), packet_type)
    offset = offset + 1

    pinfo.cols.info = string.format("Type: %s, Ver: %d", packet_type_vals[packet_type] or "Unknown", mqtt_mtd_version)

    -- Conversation data for stateful dissection (Issuer Request/Response)
    local conversation_data = nil
    if pinfo.conversation then
        conversation_data = pinfo.conversation:get_data(auth_server_proto)
        if conversation_data == nil then
            conversation_data = {} -- Initialize if not present for this conversation
            pinfo.conversation:set_data(auth_server_proto, conversation_data)
        end
    end

    -- Packet Type specific dissection
    if packet_type == 0x00 then -- Issuer Request
        local req_subtree = subtree:add(buffer(offset, pkt_len - offset), "Issuer Request Details")
        -- Issuer Request Compound Byte
        if pkt_len < offset + 1 then
            req_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Issuer Request Compound Byte"); return
            offset
        end
        local issuer_req_compound_byte = buffer(offset, 1):uint()
        local issuer_compound_subtree = req_subtree:add(pf_issuer_req_compound, buffer(offset, 1))
        local is_pub_val = (issuer_req_compound_byte >> 7) & 0x01
        local num_tokens_div4_val = issuer_req_compound_byte & 0x7F
        issuer_compound_subtree:add(pf_issuer_req_is_pub, buffer(offset, 1), is_pub_val)
        issuer_compound_subtree:add(pf_issuer_req_num_tokens_div4, buffer(offset, 1), num_tokens_div4_val)
        offset = offset + 1

        -- AEAD Algorithm
        if pkt_len < offset + 1 then
            req_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for AEAD Algorithm"); return offset
        end
        local aead_id_req = buffer(offset, 1):uint()
        req_subtree:add(pf_aead_algorithm, buffer(offset, 1), aead_id_req)
        offset = offset + 1

        -- Store info in conversation for potential response
        if conversation_data then
            conversation_data.last_issuer_req_aead_id = aead_id_req
            conversation_data.last_issuer_req_num_tokens_div4 = num_tokens_div4_val
            conversation_data.last_issuer_req_frame_num = pinfo.num -- Store frame number of this request
            -- Note: If multiple requests can be pending, this simple overwrite is a limitation.
        end

        -- Topic
        if pkt_len < offset + 2 then
            req_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Topic Length"); return offset
        end
        local topic_len = buffer(offset, 2):uint() -- Big Endian is default for :uint() on multi-byte TvbRange
        req_subtree:add(pf_topic_length, buffer(offset, 2))
        offset = offset + 2
        if pkt_len < offset + topic_len then
            req_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                "Packet too short for Topic Name (expected " .. topic_len .. " bytes)"); return offset
        end
        req_subtree:add(pf_topic_name, buffer(offset, topic_len))
        pinfo.cols.info:append(string.format(" (Topic: %s)", buffer(offset, topic_len):string())) -- Use :string() for UTF-8 with explicit length
        offset = offset + topic_len
    elseif packet_type == 0x01 then -- Issuer Response
        local resp_subtree = subtree:add(buffer(offset, pkt_len - offset), "Issuer Response Details")
        -- Status
        if pkt_len < offset + 1 then
            resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Status"); return offset
        end
        local status = buffer(offset, 1):uint()
        resp_subtree:add(pf_issuer_resp_status, buffer(offset, 1))
        offset = offset + 1
        pinfo.cols.info:append(string.format(" (Status: %s)", pf_issuer_resp_status_vals[status] or "Unknown"))

        if status == 0x01 then -- Success
            local stored_aead_id = nil
            local stored_num_tokens_div4 = nil
            local info_source_text = "Issuer Request info not found in current conversation context."

            if conversation_data and conversation_data.last_issuer_req_aead_id ~= nil and conversation_data.last_issuer_req_num_tokens_div4 ~= nil then
                stored_aead_id = conversation_data.last_issuer_req_aead_id
                stored_num_tokens_div4 = conversation_data.last_issuer_req_num_tokens_div4
                info_source_text = string.format(
                    "Using info from last Issuer Req in frame %s (AEAD: %s, NumTokens/4: %d)",
                    tostring(conversation_data.last_issuer_req_frame_num or "N/A"),
                    aead_algs_vals[stored_aead_id] or "Unknown ID",
                    stored_num_tokens_div4)
            end
            resp_subtree:add(pf_issuer_resp_info_source, nil, info_source_text) -- Add as a non-mapped string, always display
            if stored_aead_id ~= nil and stored_num_tokens_div4 ~= nil then
                -- Encryption Key
                local key_len = get_aead_key_length(stored_aead_id)
                if not key_len then
                    resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                        "Unknown AEAD algorithm from stored request data; cannot determine key length.")
                    if pkt_len > offset then resp_subtree:add(pf_issuer_resp_key, buffer(offset, pkt_len - offset)) end -- Display rest as key
                    return offset
                end
                if pkt_len < offset + key_len then
                    resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                        "Packet too short for Encryption Key (expected " .. key_len .. " bytes)"); return offset
                end
                resp_subtree:add(pf_issuer_resp_key, buffer(offset, key_len))
                offset = offset + key_len

                -- Nonce Base
                if pkt_len < offset + 12 then
                    resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                        "Packet too short for Nonce Base (expected 12 bytes)"); return offset
                end
                resp_subtree:add(pf_issuer_resp_nonce_base, buffer(offset, 12))
                offset = offset + 12

                -- Timestamp
                if pkt_len < offset + 6 then
                    resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                        "Packet too short for Timestamp (expected 6 bytes)"); return offset
                end
                resp_subtree:add(pf_issuer_resp_timestamp, buffer(offset, 6))
                offset = offset + 6

                -- All Randoms
                local num_total_tokens = stored_num_tokens_div4 * 4
                local all_randoms_len = num_total_tokens * 6 -- Each of the N tokens has a 6-byte random component
                if all_randoms_len > 0 then
                    if pkt_len < offset + all_randoms_len then
                        resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                            "Packet too short for All Randoms (expected " .. all_randoms_len .. " bytes)"); return offset
                    end
                    resp_subtree:add(pf_issuer_resp_all_randoms, buffer(offset, all_randoms_len))
                    offset = offset + all_randoms_len
                end
            else
                -- Fallback: if no request info found in conversation, show remaining payload as a single blob
                if pkt_len > offset then
                    local fallback_data_len = pkt_len - offset
                    resp_subtree:add(pf_issuer_resp_undissected_payload, buffer(offset, fallback_data_len))
                    offset = offset + fallback_data_len
                end
            end
        end
        -- No further fields for Error status or if not Success
    elseif packet_type == 0x04 then -- Verifier Request
        local req_subtree = subtree:add(buffer(offset, pkt_len - offset), "Verifier Request Details")
        -- Token
        if pkt_len < offset + 12 then
            req_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Token (expected 12 bytes)"); return
            offset
        end
        req_subtree:add(pf_verifier_req_token, buffer(offset, 12))
        pinfo.cols.info:append(string.format(" (Token: %s)", buffer(offset, 12):bytes():tohex()))
        offset = offset + 12
    elseif packet_type == 0x05 then -- Verifier Response
        local resp_subtree = subtree:add(buffer(offset, pkt_len - offset), "Verifier Response Details")
        -- Status
        if pkt_len < offset + 1 then
            resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Status"); return offset
        end
        local status = buffer(offset, 1):uint()
        resp_subtree:add(pf_verifier_resp_status, buffer(offset, 1))
        offset = offset + 1
        pinfo.cols.info:append(string.format(" (Status: %s)", pf_verifier_resp_status_vals[status] or "Unknown"))

        if status == 0x01 then -- Success
            -- Verifier Response Compound Byte
            if pkt_len < offset + 1 then
                resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                    "Packet too short for Verifier Response Compound Byte"); return offset
            end
            local verifier_resp_compound_byte = buffer(offset, 1):uint()
            local verifier_compound_subtree = resp_subtree:add(pf_verifier_resp_compound, buffer(offset, 1))
            local is_pub_val_resp = (verifier_resp_compound_byte >> 7) & 0x01
            local aead_id_resp = verifier_resp_compound_byte & 0x7F
            verifier_compound_subtree:add(pf_verifier_resp_is_pub, buffer(offset, 1), is_pub_val_resp)
            verifier_compound_subtree:add(pf_verifier_resp_aead_algo, buffer(offset, 1), aead_id_resp)
            offset = offset + 1

            -- Topic
            if pkt_len < offset + 2 then
                resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Topic Length"); return offset
            end
            local topic_len_resp = buffer(offset, 2):uint()
            resp_subtree:add(pf_topic_length, buffer(offset, 2))
            offset = offset + 2
            if pkt_len < offset + topic_len_resp then
                resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                    "Packet too short for Topic Name (expected " .. topic_len_resp .. " bytes)"); return offset
            end
            resp_subtree:add(pf_topic_name, buffer(offset, topic_len_resp))
            pinfo.cols.info:append(string.format(" (Topic: %s)", buffer(offset, topic_len_resp):string()))
            offset = offset + topic_len_resp

            -- Encryption Key
            local key_len_resp = get_aead_key_length(aead_id_resp)
            if not key_len_resp then
                resp_subtree:add_expert_info(PI_PROTOCOL, PI_WARN,
                    "Unknown AEAD algorithm in Verifier Response; cannot determine key length.")
                if pkt_len > offset then resp_subtree:add(pf_verifier_resp_key, buffer(offset, pkt_len - offset)) end -- Display rest as key
                return offset
            end
            if pkt_len < offset + key_len_resp then
                resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR,
                    "Packet too short for Encryption Key (expected " .. key_len_resp .. " bytes)"); return offset
            end
            resp_subtree:add(pf_verifier__key, buffer(offset, key_len_resp))
            offset = offset + key_len_resp

            -- Nonce
            if pkt_len < offset + 12 then
                resp_subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Packet too short for Nonce (expected 12 bytes)"); return
                offset
            end
            resp_subtree:add(pf_verifier_resp_nonce, buffer(offset, 12))
            offset = offset + 12
        end
    else
        subtree:add_expert_info(PI_PROTOCOL, PI_WARN, "Unknown packet type: " .. string.format("0x%02X", packet_type))
        if pkt_len > offset then
            subtree:add(buffer(offset, pkt_len - offset), "Unknown Payload Data")
        end
    end

    -- Check for any trailing data not dissected
    if pkt_len > offset then
        local trailing_subtree = subtree:add_expert_info(PI_MALFORMED, PI_WARN,
            "Trailing data in packet (" .. (pkt_len - offset) .. " bytes remaining)")
        trailing_subtree:add(buffer(offset, pkt_len - offset), "Undissected Trailing Data")
    end
    return pkt_len -- Return total bytes dissected (the whole packet in this case if successful)
end

-- 4. Heuristic Dissector Function
local function heuristic_check(buffer, pinfo, tree)
    -- Minimum length for magic number
    if buffer:len() < 3 then
        return false -- Not enough data for magic number
    end

    -- Check for the magic number 0x4D51ED at the beginning of the packet
    -- buffer(offset, length):uint() reads in Big Endian by default, which is what we want for network protocols.
    if buffer(0, 3):uint() == 0x4D51ED then
        -- Magic number matches, call the main dissector
        auth_server_proto.dissector(buffer, pinfo, tree)
        return true -- Signal that this dissector handled the packet
    end

    return false -- Magic number does not match, not our protocol
end

-- 5. Register the Heuristic Dissector for both TCP and UDP
-- This allows Wireshark to try this dissector on any TCP/UDP packet
-- if no port-specific dissector has claimed it.
auth_server_proto:register_heuristic("tcp", heuristic_check)
auth_server_proto:register_heuristic("udp", heuristic_check)

print("Auth Server Protocol Dissector (Heuristic, with Conversation Tracking) Loaded")

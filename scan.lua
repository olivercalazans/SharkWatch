do
    local portscanner = Proto("portscanner", "Passive Port Scanner")

    -- Main dissector
    function portscanner.dissector(buffer, pinfo, tree)
        -- Check if it's a TCP packet
        if pinfo.tcp then
            local src_ip = tostring(pinfo.src)
            local dst_ip = tostring(pinfo.dst)
            local dst_port = tostring(pinfo.dst_port)

            -- Extract TCP flags
            local flags = buffer(33, 1):uint()
            local syn_flag = (flags & 0x02) >> 1
            local ack_flag = (flags & 0x10) >> 4
            local rst_flag = (flags & 0x04) >> 2

            -- Add information to the tree
            local subtree = tree:add(portscanner, "Passive Port Scanner")
            subtree:add("Source IP: " .. src_ip)
            subtree:add("Destination IP: " .. dst_ip)
            subtree:add("Destination Port: " .. dst_port)
            subtree:add("SYN: " .. syn_flag .. ", ACK: " .. ack_flag .. ", RST: " .. rst_flag)

            -- Determine the port state
            if syn_flag == 1 and ack_flag == 1 then
                subtree:add("Port State: Open")
            elseif rst_flag == 1 then
                subtree:add("Port State: Closed")
            else
                subtree:add("Port State: Indeterminate")
            end
        end

        -- Check if it's a UDP packet
        if pinfo.udp then
            local src_ip = tostring(pinfo.src)
            local dst_ip = tostring(pinfo.dst)
            local dst_port = tostring(pinfo.dst_port)

            -- Add information to the tree
            local subtree = tree:add(portscanner, "Passive Port Scanner")
            subtree:add("Source IP: " .. src_ip)
            subtree:add("Destination IP: " .. dst_ip)
            subtree:add("Destination Port: " .. dst_port)
            subtree:add("Protocol: UDP")

            -- In UDP, port state is harder to determine without ICMP
            subtree:add("Port State: Possibly Open (based on UDP traffic)")
        end
    end

    -- Register the post-dissector
    register_postdissector(portscanner)
end

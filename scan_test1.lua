-- Criação do dissector para um protocolo personalizado
local my_proto = Proto("myproto", "Mostrar IPs de Origem e Destino")

-- Função que processa os pacotes
function my_proto.dissector(buffer, pinfo, tree)
    -- Definindo que o protocolo será "MYPROTO"
    pinfo.cols.protocol = "MYPROTO"
    
    -- Criando uma árvore de dissecação para o pacote
    local subtree = tree:add(my_proto, buffer(), "Dados do Protocolo")
    
    -- Verificando se o pacote é IP
    if pinfo.dst ~= nil and pinfo.src ~= nil then
        local src_ip = tostring(pinfo.src)
        local dst_ip = tostring(pinfo.dst)
        
        -- Mostrando apenas os IPs de origem e destino
        subtree:add(buffer(0, 4), "IP de Origem: " .. src_ip)
        subtree:add(buffer(4, 4), "IP de Destino: " .. dst_ip)
        
        -- Exibindo os IPs de forma limpa sem outros dados
        pinfo.cols.info = "Origem: " .. src_ip .. " Destino: " .. dst_ip
    end
end

-- Registrando o dissector para pacotes IP
DissectorTable.get("ip"):add(0, my_proto)

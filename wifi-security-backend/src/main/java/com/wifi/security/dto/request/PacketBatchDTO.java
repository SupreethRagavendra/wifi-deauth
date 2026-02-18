package com.wifi.security.dto.request;

import lombok.Data;
import java.util.List;

@Data
public class PacketBatchDTO {
    private List<PacketDTO> packets;
}

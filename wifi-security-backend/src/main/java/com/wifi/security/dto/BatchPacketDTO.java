package com.wifi.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@Data
@NoArgsConstructor
public class BatchPacketDTO {
    private List<DeauthPacketDTO> packets;
}

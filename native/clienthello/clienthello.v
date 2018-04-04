`timescale  1ns/1ns
`default_nettype wire

module parser_wrapper #(
  parameter C_BUS_DATA_WIDTH = 512                 ,
  parameter C_BUS_KEEP_WIDTH = (C_BUS_DATA_WIDTH/8)
) (
  input  wire                        CLK              ,
  input  wire                        RST_N            ,
  //Input AXI4-Stream interface
  input  wire [C_BUS_DATA_WIDTH-1:0] IN_PACKET_TDATA  ,
  output wire                        IN_PACKET_TREADY ,
  input  wire                        IN_PACKET_TVALID ,
  input  wire                        IN_PACKET_TLAST  ,
  input  wire [C_BUS_KEEP_WIDTH-1:0] IN_PACKET_TKEEP  ,
  //Output AXI4-Stream interface
  output wire [C_BUS_DATA_WIDTH-1:0] OUT_PACKET_TDATA ,
  input  wire                        OUT_PACKET_TREADY,
  output wire                        OUT_PACKET_TVALID,
  output wire                        OUT_PACKET_TLAST ,
  output wire [C_BUS_KEEP_WIDTH-1:0] OUT_PACKET_TKEEP ,
  output wire                        RULE_TDATA       ,
  output wire                        RULE_TVALID
);
  assign OUT_PACKET_TDATA  = IN_PACKET_TDATA;
  assign IN_PACKET_TREADY  = OUT_PACKET_TREADY;
  assign OUT_PACKET_TVALID = IN_PACKET_TVALID;
  assign OUT_PACKET_TLAST  = IN_PACKET_TLAST;
  assign OUT_PACKET_TKEEP  = IN_PACKET_TKEEP;

  reg [C_BUS_DATA_WIDTH-1:0] data ;
  reg                        valid;
  reg                        last ;
  always @(posedge CLK or negedge RST_N) begin : proc_reg_data
    if(~RST_N) begin
      data  <= 0;
      valid <= 0;
      last  <= 0;
    end else begin
      if(IN_PACKET_TVALID&IN_PACKET_TREADY) begin
        last  <= IN_PACKET_TLAST;
        data  <= IN_PACKET_TDATA;
        valid <= 1'b1;
      end else begin
        valid <= 1'b0;
      end
    end
  end

  reg new_pkt;
  always @(posedge CLK or negedge RST_N) begin : proc_new_pkt
    if(~RST_N) begin
      new_pkt <= 1'b1;
    end else begin
      if(valid&last) begin
        new_pkt <= 1'b1;
      end else if(valid) begin
        new_pkt <= 1'b0;
      end
    end
  end

  localparam LENGTH_ETHERNET = 14*8                       ;
  localparam LENGTH_IPV4     = 20*8                       ;
  localparam LENGTH_TCP      = 20*8                       ;
  localparam OFFSET_IP       = LENGTH_ETHERNET            ;
  localparam OFFSET_TCP_IPV4 = LENGTH_ETHERNET+LENGTH_IPV4;
  reg        rule                                         ;
  reg        candidate                                    ;
  reg        rule_asserted                                ;
  reg        rule_valid                                   ;
  wire       has_vlan                                     ;
  wire is_ipv4;
  assign is_ipv4 = data[96+:16]==16'h0008;
  wire is_tcp_ipv4;
  assign is_tcp_ipv4 = data[OFFSET_IP+72+:8]==8'h06;
  wire is_tcp_ipv4_port_443;
  assign is_tcp_ipv4_port_443 = data[OFFSET_TCP_IPV4+:16]==16'hbb01||data[OFFSET_TCP_IPV4+16+:16]==16'hbb01;
  wire [8:0] tcp_offset;
  assign tcp_offset = {data[OFFSET_TCP_IPV4+100+:4], 5'h0};
  reg [7:0] ssl_offset_r;
  wire [7:0] ssl_offset;
  assign ssl_offset  = tcp_offset+OFFSET_TCP_IPV4;
  wire is_content_type_22;
  assign is_content_type_22  = data[ssl_offset_r+:8]==8'd22;
  wire is_handshake_type_01;
  assign is_handshake_type_01  = data[ssl_offset_r+40+:8]==8'd01;

  assign RULE_TDATA  = rule;
  assign RULE_TVALID = rule_valid;
  always @(posedge CLK or negedge RST_N) begin : proc_rule
    if(~RST_N) begin
      rule       <= 0;
      rule_valid <= 0;
      rule_asserted <= 0;
      ssl_offset_r  <= 0;
    end else begin
      if(valid&new_pkt) begin
        candidate <= (is_ipv4 && is_tcp_ipv4 && is_tcp_ipv4_port_443);  
        ssl_offset_r <= ssl_offset;
        rule_asserted <= 1'b0;
        if(last) begin // Exception: packets of size equal or less than 64B
          rule <= 1'b0;
          rule_valid <= 1'b1;
        end else begin
          rule_valid <= 1'b0;
        end
      end else if(valid&!rule_asserted) begin
        if(candidate) begin
          rule <= is_content_type_22 & is_handshake_type_01;
        end else begin
          rule <= 1'b0;
        end
        rule_valid <= 1'b1;
        rule_asserted <= 1'b1;
      end else if(rule_valid) begin
        rule_valid <= 1'b0;
      end
    end
  end

endmodule

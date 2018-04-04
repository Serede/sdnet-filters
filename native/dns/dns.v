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
  localparam LENGTH_VLAN     = 4*8                        ;
  localparam LENGTH_IPV4     = 20*8                       ;
  localparam LENGTH_IPV6     = 38*8                       ;
  localparam LENGTH_UDP      = 8*8                        ;
  localparam OFFSET_IP       = LENGTH_ETHERNET            ;
  localparam OFFSET_UDP_IPV4 = LENGTH_ETHERNET+LENGTH_IPV4;
  localparam OFFSET_UDP_IPV6 = LENGTH_ETHERNET+LENGTH_IPV6;
  reg        rule                                         ;
  reg        rule_valid                                   ;
  wire       has_vlan                                     ;
  assign has_vlan = data[96+:16]==16'h0081;
  wire has_nested_vlan;
  assign has_nested_vlan = data[LENGTH_ETHERNET+16+:16]==16'h0081;
  wire is_ipv4;
  assign is_ipv4 = data[96+:16]==16'h0008;
  wire is_ipv4_inside_vlan;
  assign is_ipv4_inside_vlan = data[LENGTH_ETHERNET+16+:16]==16'h0008;
  wire is_ipv4_inside_nested_vlan;
  assign is_ipv4_inside_nested_vlan = data[LENGTH_ETHERNET+LENGTH_VLAN+16+:16]==16'h0008;
  wire is_ipv6;
  assign is_ipv6 = data[96+:16]==16'hdd86;
  wire is_ipv6_inside_vlan;
  assign is_ipv6_inside_vlan = data[LENGTH_ETHERNET+16+:16]==16'hdd86;
  wire is_ipv6_inside_nested_vlan;
  assign is_ipv6_inside_nested_vlan = data[LENGTH_ETHERNET+LENGTH_VLAN+16+:16]==16'hdd86;
  wire is_udp_ipv4;
  assign is_udp_ipv4 = data[OFFSET_IP+72+:8]==8'h11;
  wire is_udp_ipv4_inside_vlan;
  assign is_udp_ipv4_inside_vlan = data[OFFSET_IP+LENGTH_VLAN+72+:8]==8'h11;
  wire is_udp_ipv4_inside_nested_vlan;
  assign is_udp_ipv4_inside_nested_vlan = data[OFFSET_IP+2*LENGTH_VLAN+72+:8]==8'h11;
  wire is_udp_ipv6;
  assign is_udp_ipv6 = data[OFFSET_IP+32+:8]==8'h11;
  wire is_udp_ipv6_inside_vlan;
  assign is_udp_ipv6_inside_vlan = data[OFFSET_IP+LENGTH_VLAN+32+:8]==8'h11;
  wire is_udp_ipv6_inside_nested_vlan;
  assign is_udp_ipv6_inside_nested_vlan = data[OFFSET_IP+2*LENGTH_VLAN+32+:8]==8'h11;
  wire is_udp_ipv4_port_53;
  assign is_udp_ipv4_port_53 = data[OFFSET_UDP_IPV4+:16]==16'h3500||data[OFFSET_UDP_IPV4+16+:16]==16'h3500;
  wire is_udp_ipv4_port_53_inside_vlan;
  assign is_udp_ipv4_port_53_inside_vlan = data[OFFSET_UDP_IPV4+LENGTH_VLAN+:16]==16'h3500||data[OFFSET_UDP_IPV4+LENGTH_VLAN+16+:16]==16'h3500;
  wire is_udp_ipv4_port_53_inside_nested_vlan;
  assign is_udp_ipv4_port_53_inside_nested_vlan = data[OFFSET_UDP_IPV4+2*LENGTH_VLAN+:16]==16'h3500||data[OFFSET_UDP_IPV4+2*LENGTH_VLAN+16+:16]==16'h3500;
  wire is_udp_ipv6_port_53;
  assign is_udp_ipv6_port_53 = data[OFFSET_UDP_IPV6+:16]==16'h3500||data[OFFSET_UDP_IPV6+16+:16]==16'h3500;
  wire is_udp_ipv6_port_53_inside_vlan;
  assign is_udp_ipv6_port_53_inside_vlan = data[OFFSET_UDP_IPV6+LENGTH_VLAN+:16]==16'h3500||data[OFFSET_UDP_IPV6+LENGTH_VLAN+16+:16]==16'h3500;
  wire is_udp_ipv6_port_53_inside_nested_vlan;
  assign is_udp_ipv6_port_53_inside_nested_vlan = data[OFFSET_UDP_IPV6+2*LENGTH_VLAN+:16]==16'h3500||data[OFFSET_UDP_IPV6+2*LENGTH_VLAN+16+:16]==16'h3500;


  assign RULE_TDATA  = rule;
  assign RULE_TVALID = rule_valid;
  always @(posedge CLK or negedge RST_N) begin : proc_rule
    if(~RST_N) begin
      rule       <= 0;
      rule_valid <= 0;
    end else begin
      if(valid&new_pkt) begin
        rule <= (is_ipv4 && is_udp_ipv4 && is_udp_ipv4_port_53)  ||
          (has_vlan && is_ipv4_inside_vlan && is_udp_ipv4_inside_vlan && is_udp_ipv4_port_53_inside_vlan)  ||
          (has_nested_vlan && is_ipv4_inside_nested_vlan && is_udp_ipv4_inside_nested_vlan && is_udp_ipv4_port_53_inside_nested_vlan)  ||
          (is_ipv6 && is_udp_ipv6 && is_udp_ipv6_port_53)  ||
          (has_vlan && is_ipv6_inside_vlan && is_udp_ipv6_inside_vlan && is_udp_ipv6_port_53_inside_vlan)  ||
          (has_nested_vlan && is_ipv6_inside_nested_vlan && is_udp_ipv6_inside_nested_vlan && is_udp_ipv6_port_53_inside_nested_vlan);
        rule_valid <= 1'b1;
      end else if(rule_valid) begin
        rule_valid <= 1'b0;
      end
    end
  end

endmodule

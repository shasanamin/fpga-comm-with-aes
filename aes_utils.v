/*generate keys for each round using cipher key, which is
already a result of many hashing and cryptographic transformations 
on secret cryptographic master key with admin.*/
module getRoundKeys(output [127:0] outKey, input [127:0] inKey, [3:0] roundNum);
	wire [31:0] w0, w1, w2, w3, temp;
	reg [31:0] rcon;
	
	assign w0 = inKey[127:96];
	assign w1 = inKey[95:64];
	assign w2 = inKey[63:32];
	assign w3 = inKey[31:0];
	
	// get values of rcon from special table
	// values: 2,4,8,16,32,64,128,27,54,108
	// value goes from 128 to 27 because of the way finite fields overflow
	always @(*)
	begin
		case (roundNum)
			4'h0: rcon=32'h01000000;
        	 	4'h1: rcon=32'h02000000;
        	 	4'h2: rcon=32'h04000000;
			4'h3: rcon=32'h08000000;
			4'h4: rcon=32'h10000000;
        	 	4'h5: rcon=32'h20000000;
        	 	4'h6: rcon=32'h40000000;
        	 	4'h7: rcon=32'h80000000;
        	 	4'h8: rcon=32'h1b000000;
        	 	4'h9: rcon=32'h36000000;
        	 	default: rcon=32'h00000000;
		endcase
	end

       	assign outKey[127:96]= w0 ^ temp ^ rcon;
       	assign outKey[95:64] = w0 ^ temp ^ rcon ^ w1;
       	assign outKey[63:32] = w0 ^ temp ^ rcon ^ w1 ^ w2;
       	assign outKey[31:0]  = w0 ^ temp ^ rcon ^ w1 ^ w2 ^ w3;

       	sbox a1(.toReplace(w3[23:16]),.sub(temp[31:24]));
       	sbox a2(.toReplace(w3[15:8]),.sub(temp[23:16]));
       	sbox a3(.toReplace(w3[7:0]),.sub(temp[15:8]));
       	sbox a4(.toReplace(w3[31:24]),.sub(temp[7:0]));
endmodule


// key for first inverse round (named inv_roundLast) is same as key for roundLast in encryption
// key for second inverse round is same as key for ninth round in encryption
// module getinvRoundKeys returns ten 128-bit keys with invRoundKeys[127:0] referring to key for first inverse round
// mKey refers to the (transformed) master key used in first round of encryption
module getInvRoundKeys(output [1279:0] invRoundKeys, input [127:0] mKey);
	getRoundKeys g1(.outKey(invRoundKeys[1279:1152]), .inKey(mKey), .roundNum(4'b0000));
	getRoundKeys g2(.outKey(invRoundKeys[1151:1024]), .inKey(invRoundKeys[1279:1152]), .roundNum(4'b0001));
	getRoundKeys g3(.outKey(invRoundKeys[1023:896]), .inKey(invRoundKeys[1151:1024]), .roundNum(4'b0010));
	getRoundKeys g4(.outKey(invRoundKeys[895:768]), .inKey(invRoundKeys[1023:896]), .roundNum(4'b0011));
	getRoundKeys g5(.outKey(invRoundKeys[767:640]), .inKey(invRoundKeys[895:768]), .roundNum(4'b0100));
	getRoundKeys g6(.outKey(invRoundKeys[639:512]), .inKey(invRoundKeys[767:640]), .roundNum(4'b0101));
	getRoundKeys g7(.outKey(invRoundKeys[511:384]), .inKey(invRoundKeys[639:512]), .roundNum(4'b0110));
	getRoundKeys g8(.outKey(invRoundKeys[383:256]), .inKey(invRoundKeys[511:384]), .roundNum(4'b0111));
	getRoundKeys g9(.outKey(invRoundKeys[255:128]), .inKey(invRoundKeys[383:256]), .roundNum(4'b1000));
	getRoundKeys g10(.outKey(invRoundKeys[127:0]), .inKey(invRoundKeys[255:128]), .roundNum(4'b1001));
endmodule


// substitute data bytes (to translate data)
module subBytes(output [127:0] sub, input [127:0] data);
	sbox q0(.toReplace(data[127:120]),.sub(sub[127:120]));
     	sbox q1(.toReplace(data[119:112]),.sub(sub[119:112]));
     	sbox q2(.toReplace(data[111:104]),.sub(sub[111:104]));
     	sbox q3(.toReplace(data[103:96]),.sub(sub[103:96]));
     	sbox q4(.toReplace(data[95:88]),.sub(sub[95:88]));
     	sbox q5(.toReplace(data[87:80]),.sub(sub[87:80]));
     	sbox q6(.toReplace(data[79:72]),.sub(sub[79:72]));
     	sbox q7(.toReplace(data[71:64]),.sub(sub[71:64]));
     	sbox q8(.toReplace(data[63:56]),.sub(sub[63:56]));
     	sbox q9(.toReplace(data[55:48]),.sub(sub[55:48]));
     	sbox q10(.toReplace(data[47:40]),.sub(sub[47:40]));
     	sbox q11(.toReplace(data[39:32]),.sub(sub[39:32]));
     	sbox q12(.toReplace(data[31:24]),.sub(sub[31:24]) );
     	sbox q13(.toReplace(data[23:16]),.sub(sub[23:16]) );
     	sbox q14(.toReplace(data[15:8]),.sub(sub[15:8]) );
     	sbox q16(.toReplace(data[7:0]),.sub(sub[7:0]) );
endmodule


// reverse substitution of bytes
module inv_subBytes(output [127:0] sub, input [127:0] data);
	inv_sbox q0(.toReplace(data[127:120]),.sub(sub[127:120]));
     	inv_sbox q1(.toReplace(data[119:112]),.sub(sub[119:112]));
     	inv_sbox q2(.toReplace(data[111:104]),.sub(sub[111:104]));
     	inv_sbox q3(.toReplace(data[103:96]),.sub(sub[103:96]));
     	inv_sbox q4(.toReplace(data[95:88]),.sub(sub[95:88]));
     	inv_sbox q5(.toReplace(data[87:80]),.sub(sub[87:80]));
     	inv_sbox q6(.toReplace(data[79:72]),.sub(sub[79:72]));
     	inv_sbox q7(.toReplace(data[71:64]),.sub(sub[71:64]));
     	inv_sbox q8(.toReplace(data[63:56]),.sub(sub[63:56]));
     	inv_sbox q9(.toReplace(data[55:48]),.sub(sub[55:48]));
     	inv_sbox q10(.toReplace(data[47:40]),.sub(sub[47:40]));
     	inv_sbox q11(.toReplace(data[39:32]),.sub(sub[39:32]));
     	inv_sbox q12(.toReplace(data[31:24]),.sub(sub[31:24]) );
     	inv_sbox q13(.toReplace(data[23:16]),.sub(sub[23:16]) );
     	inv_sbox q14(.toReplace(data[15:8]),.sub(sub[15:8]) );
     	inv_sbox q16(.toReplace(data[7:0]),.sub(sub[7:0]) );
endmodule


// right shift ith byte row by (i-1) bytes
// first row remains unchanged, second row right shifted by 1 byte, and so on
module shiftRow(output [127:0] shifted, input [127:0] data);
	assign shifted[127:120] = data[127:120];  
	assign shifted[119:112] = data[87:80];
	assign shifted[111:104] = data[47:40];
	assign shifted[103:96] = data[7:0];

	assign shifted[95:88] = data[95:88];
	assign shifted[87:80] = data[55:48];
	assign shifted[79:72] = data[15:8];
	assign shifted[71:64] = data[103:96];
	   
	assign shifted[63:56] = data[63:56];
	assign shifted[55:48] = data[23:16];
	assign shifted[47:40] = data[111:104];
	assign shifted[39:32] = data[71:64];
	   
	assign shifted[31:24] = data[31:24];
	assign shifted[23:16] = data[119:112];
	assign shifted[15:8] = data[79:72];
	assign shifted[7:0] = data[39:32]; 
endmodule


// left shift ith byte row by (i-1) bytes
// first row remains unchanged, second row left shifted by 1 byte, and so on
module inv_shiftRow(output [127:0] data, input [127:0] shifted);
	assign data[127:120] = shifted[127:120];  
	assign data[87:80] = shifted[119:112];
	assign data[47:40] = shifted[111:104];
	assign data[7:0] = shifted[103:96];
	   
	assign data[95:88] = shifted[95:88];
	assign data[55:48] = shifted[87:80];
	assign data[15:8] = shifted[79:72];
	assign data[103:96] = shifted[71:64];
	   
	assign data[63:56] = shifted[63:56];
	assign data[23:16] = shifted[55:48];
	assign data[111:104] = shifted[47:40];
	assign data[71:64] = shifted[39:32];
	   
	assign data[31:24] = shifted[31:24];
	assign data[119:112] = shifted[23:16];
	assign data[79:72] = shifted[15:8];
	assign data[39:32] = shifted[7:0];
endmodule


// two implementations of mixColumns provided (use only one and comment the other)
// one performs matrix multiplication (takes more time), while other uses lookup tables (takes more space)

// take each column from state array and replace it with new column computed by specific matrix multiplication
// 'hardcoding' required matrix multiplication, instead of implementing a generic Galois field multiplication module
/*module mixColumns(output [127:0] aNew, input [127:0] a);
	function [7:0] mixByte;  //functions are synthesizable
		input [7:0] i1,i2,i3,i4; 
		begin
			mixByte[7] = i1[6] ^ i2[6] ^ i2[7] ^ i3[7] ^ i4[7];
			mixByte[6] = i1[5] ^ i2[5] ^ i2[6] ^ i3[6] ^ i4[6];
			mixByte[5] = i1[4] ^ i2[4] ^ i2[5] ^ i3[5] ^ i4[5];
			mixByte[4] = i1[3] ^ i1[7] ^ i2[3] ^ i2[4] ^ i2[7] ^ i3[4] ^ i4[4];
			mixByte[3] = i1[2] ^ i1[7] ^ i2[2] ^ i2[3] ^ i2[7] ^ i3[3] ^ i4[3];
			mixByte[2] = i1[1] ^ i2[1] ^ i2[2] ^ i3[2] ^ i4[2];
			mixByte[1] = i1[0] ^ i1[7] ^ i2[0] ^ i2[1] ^ i2[7] ^ i3[1] ^ i4[1];
			mixByte[0] = i1[7] ^ i2[7] ^ i2[0] ^ i3[0] ^ i4[0];
		end
	endfunction

	// mixing first column
	assign aNew[127:120] = mixByte (a[127:120],a[119:112],a[111:104],a[103:96]);
	assign aNew[119:112] = mixByte (a[119:112],a[111:104],a[103:96],a[127:120]);
	assign aNew[111:104] = mixByte (a[111:104],a[103:96],a[127:120],a[119:112]);
	assign aNew[103:96] = mixByte (a[103:96],a[127:120],a[119:112],a[111:104]);

	// mixing second column
	assign aNew[95:88] = mixByte (a[95:88],a[87:80],a[79:72],a[71:64]);
	assign aNew[87:80] = mixByte (a[87:80],a[79:72],a[71:64],a[95:88]);
	assign aNew[79:72] = mixByte (a[79:72],a[71:64],a[95:88],a[87:80]);
	assign aNew[71:64] = mixByte (a[71:64],a[95:88],a[87:80],a[79:72]);

	// mixing third column
	assign aNew[63:56]  = mixByte (a[63:56],a[55:48],a[47:40],a[39:32]);
	assign aNew[55:48]  = mixByte (a[55:48],a[47:40],a[39:32],a[63:56]);
	assign aNew[47:40]  = mixByte (a[47:40],a[39:32],a[63:56],a[55:48]);
	assign aNew[39:32]  = mixByte (a[39:32],a[63:56],a[55:48],a[47:40]);

	// mixing fourth column
	assign aNew[31:24]  = mixByte (a[31:24],a[23:16],a[15:8],a[7:0]);
	assign aNew[23:16]  = mixByte (a[23:16],a[15:8],a[7:0],a[31:24]);
	assign aNew[15:8]   = mixByte (a[15:8],a[7:0],a[31:24],a[23:16]);
	assign aNew[7:0]    = mixByte (a[7:0],a[31:24],a[23:16],a[15:8]);
endmodule*/


module mixColumns(output [127:0] aNew, input [127:0] a);
	reg [2047:0] galoisM2 = {8'h00,8'h02,8'h04,8'h06,8'h08,8'h0a,8'h0c,8'h0e,8'h10,8'h12,8'h14,8'h16,8'h18,8'h1a,8'h1c,8'h1e, 8'h20,8'h22,8'h24,8'h26,8'h28,8'h2a,8'h2c,8'h2e,8'h30,8'h32,8'h34,8'h36,8'h38,8'h3a,8'h3c,8'h3e, 8'h40,8'h42,8'h44,8'h46,8'h48,8'h4a,8'h4c,8'h4e,8'h50,8'h52,8'h54,8'h56,8'h58,8'h5a,8'h5c,8'h5e, 8'h60,8'h62,8'h64,8'h66,8'h68,8'h6a,8'h6c,8'h6e,8'h70,8'h72,8'h74,8'h76,8'h78,8'h7a,8'h7c,8'h7e, 8'h80,8'h82,8'h84,8'h86,8'h88,8'h8a,8'h8c,8'h8e,8'h90,8'h92,8'h94,8'h96,8'h98,8'h9a,8'h9c,8'h9e, 8'ha0,8'ha2,8'ha4,8'ha6,8'ha8,8'haa,8'hac,8'hae,8'hb0,8'hb2,8'hb4,8'hb6,8'hb8,8'hba,8'hbc,8'hbe, 8'hc0,8'hc2,8'hc4,8'hc6,8'hc8,8'hca,8'hcc,8'hce,8'hd0,8'hd2,8'hd4,8'hd6,8'hd8,8'hda,8'hdc,8'hde, 8'he0,8'he2,8'he4,8'he6,8'he8,8'hea,8'hec,8'hee,8'hf0,8'hf2,8'hf4,8'hf6,8'hf8,8'hfa,8'hfc,8'hfe, 8'h1b,8'h19,8'h1f,8'h1d,8'h13,8'h11,8'h17,8'h15,8'h0b,8'h09,8'h0f,8'h0d,8'h03,8'h01,8'h07,8'h05, 8'h3b,8'h39,8'h3f,8'h3d,8'h33,8'h31,8'h37,8'h35,8'h2b,8'h29,8'h2f,8'h2d,8'h23,8'h21,8'h27,8'h25, 8'h5b,8'h59,8'h5f,8'h5d,8'h53,8'h51,8'h57,8'h55,8'h4b,8'h49,8'h4f,8'h4d,8'h43,8'h41,8'h47,8'h45, 8'h7b,8'h79,8'h7f,8'h7d,8'h73,8'h71,8'h77,8'h75,8'h6b,8'h69,8'h6f,8'h6d,8'h63,8'h61,8'h67,8'h65, 8'h9b,8'h99,8'h9f,8'h9d,8'h93,8'h91,8'h97,8'h95,8'h8b,8'h89,8'h8f,8'h8d,8'h83,8'h81,8'h87,8'h85, 8'hbb,8'hb9,8'hbf,8'hbd,8'hb3,8'hb1,8'hb7,8'hb5,8'hab,8'ha9,8'haf,8'had,8'ha3,8'ha1,8'ha7,8'ha5, 8'hdb,8'hd9,8'hdf,8'hdd,8'hd3,8'hd1,8'hd7,8'hd5,8'hcb,8'hc9,8'hcf,8'hcd,8'hc3,8'hc1,8'hc7,8'hc5, 8'hfb,8'hf9,8'hff,8'hfd,8'hf3,8'hf1,8'hf7,8'hf5,8'heb,8'he9,8'hef,8'hed,8'he3,8'he1,8'he7,8'he5};
	reg [2047:0] galoisM3 = {8'h00,8'h03,8'h06,8'h05,8'h0c,8'h0f,8'h0a,8'h09,8'h18,8'h1b,8'h1e,8'h1d,8'h14,8'h17,8'h12,8'h11, 8'h30,8'h33,8'h36,8'h35,8'h3c,8'h3f,8'h3a,8'h39,8'h28,8'h2b,8'h2e,8'h2d,8'h24,8'h27,8'h22,8'h21, 8'h60,8'h63,8'h66,8'h65,8'h6c,8'h6f,8'h6a,8'h69,8'h78,8'h7b,8'h7e,8'h7d,8'h74,8'h77,8'h72,8'h71, 8'h50,8'h53,8'h56,8'h55,8'h5c,8'h5f,8'h5a,8'h59,8'h48,8'h4b,8'h4e,8'h4d,8'h44,8'h47,8'h42,8'h41, 8'hc0,8'hc3,8'hc6,8'hc5,8'hcc,8'hcf,8'hca,8'hc9,8'hd8,8'hdb,8'hde,8'hdd,8'hd4,8'hd7,8'hd2,8'hd1, 8'hf0,8'hf3,8'hf6,8'hf5,8'hfc,8'hff,8'hfa,8'hf9,8'he8,8'heb,8'hee,8'hed,8'he4,8'he7,8'he2,8'he1, 8'ha0,8'ha3,8'ha6,8'ha5,8'hac,8'haf,8'haa,8'ha9,8'hb8,8'hbb,8'hbe,8'hbd,8'hb4,8'hb7,8'hb2,8'hb1, 8'h90,8'h93,8'h96,8'h95,8'h9c,8'h9f,8'h9a,8'h99,8'h88,8'h8b,8'h8e,8'h8d,8'h84,8'h87,8'h82,8'h81, 8'h9b,8'h98,8'h9d,8'h9e,8'h97,8'h94,8'h91,8'h92,8'h83,8'h80,8'h85,8'h86,8'h8f,8'h8c,8'h89,8'h8a, 8'hab,8'ha8,8'had,8'hae,8'ha7,8'ha4,8'ha1,8'ha2,8'hb3,8'hb0,8'hb5,8'hb6,8'hbf,8'hbc,8'hb9,8'hba, 8'hfb,8'hf8,8'hfd,8'hfe,8'hf7,8'hf4,8'hf1,8'hf2,8'he3,8'he0,8'he5,8'he6,8'hef,8'hec,8'he9,8'hea, 8'hcb,8'hc8,8'hcd,8'hce,8'hc7,8'hc4,8'hc1,8'hc2,8'hd3,8'hd0,8'hd5,8'hd6,8'hdf,8'hdc,8'hd9,8'hda, 8'h5b,8'h58,8'h5d,8'h5e,8'h57,8'h54,8'h51,8'h52,8'h43,8'h40,8'h45,8'h46,8'h4f,8'h4c,8'h49,8'h4a, 8'h6b,8'h68,8'h6d,8'h6e,8'h67,8'h64,8'h61,8'h62,8'h73,8'h70,8'h75,8'h76,8'h7f,8'h7c,8'h79,8'h7a, 8'h3b,8'h38,8'h3d,8'h3e,8'h37,8'h34,8'h31,8'h32,8'h23,8'h20,8'h25,8'h26,8'h2f,8'h2c,8'h29,8'h2a, 8'h0b,8'h08,8'h0d,8'h0e,8'h07,8'h04,8'h01,8'h02,8'h13,8'h10,8'h15,8'h16,8'h1f,8'h1c,8'h19,8'h1a};

	assign aNew[127:120] = galoisM2[a[127:120]] ^ a[119:112] ^ a[111:104] ^ galoisM3[a[103:96]];
	assign aNew[119:112] = galoisM3[a[127:120]] ^ galoisM2[a[119:112]] ^ a[111:104] ^ a[103:96];
	assign aNew[111:104] = a[127:120] ^ galoisM3[a[119:112]] ^ galoisM2[a[111:104]] ^ a[103:96];
	assign aNew[103:96] = a[127:120] ^ a[119:112] ^ galoisM3[a[111:104]] ^ galoisM2[a[103:96]];

	assign aNew[95:88] = galoisM2[a[95:88]] ^ a[87:80] ^ a[79:72] ^ galoisM3[a[71:64]];
	assign aNew[87:80] = galoisM3[a[95:88]] ^ galoisM2[a[87:80]] ^ a[79:72] ^ a[71:64];
	assign aNew[79:72] = a[95:88] ^ galoisM3[a[87:80]] ^ galoisM2[a[79:72]] ^ a[71:64];
	assign aNew[71:64] = a[95:88] ^ a[87:80] ^ galoisM3[a[79:72]] ^ galoisM2[a[71:64]];

	assign aNew[63:56] = galoisM2[a[63:56]] ^ a[55:48] ^ a[47:40] ^ galoisM3[a[39:32]];
	assign aNew[55:48] = galoisM3[a[63:56]] ^ galoisM2[a[55:48]] ^ a[47:40] ^ a[39:32];
	assign aNew[47:40] = a[63:56] ^ galoisM3[a[55:48]] ^ galoisM2[a[47:40]] ^ a[39:32];
	assign aNew[39:32] = a[63:56] ^ a[55:48] ^ galoisM3[a[47:40]] ^ galoisM2[a[39:32]];

	assign aNew[31:24] = galoisM2[a[31:24]] ^ a[23:16] ^ a[15:8] ^ galoisM3[a[7:0]];
	assign aNew[23:16] = galoisM3[a[31:24]] ^ galoisM2[a[23:16]] ^ a[15:8] ^ a[7:0];
	assign aNew[15:8] = a[31:24] ^ galoisM3[a[23:16]] ^ galoisM2[a[15:8]] ^ a[7:0];
	assign aNew[7:0] = a[31:24] ^ a[23:16] ^ galoisM3[a[15:8]] ^ galoisM2[a[7:0]];
endmodule


// matrix multiplication for inverse mixing does not give a neat expression, so will use just lookup tables here
module inv_mixColumns(output [127:0] aNew, input [127:0] a);
	reg [2047:0] galoisM9 = {8'h00,8'h09,8'h12,8'h1b,8'h24,8'h2d,8'h36,8'h3f,8'h48,8'h41,8'h5a,8'h53,8'h6c,8'h65,8'h7e,8'h77, 8'h90,8'h99,8'h82,8'h8b,8'hb4,8'hbd,8'ha6,8'haf,8'hd8,8'hd1,8'hca,8'hc3,8'hfc,8'hf5,8'hee,8'he7, 8'h3b,8'h32,8'h29,8'h20,8'h1f,8'h16,8'h0d,8'h04,8'h73,8'h7a,8'h61,8'h68,8'h57,8'h5e,8'h45,8'h4c, 8'hab,8'ha2,8'hb9,8'hb0,8'h8f,8'h86,8'h9d,8'h94,8'he3,8'hea,8'hf1,8'hf8,8'hc7,8'hce,8'hd5,8'hdc, 8'h76,8'h7f,8'h64,8'h6d,8'h52,8'h5b,8'h40,8'h49,8'h3e,8'h37,8'h2c,8'h25,8'h1a,8'h13,8'h08,8'h01, 8'he6,8'hef,8'hf4,8'hfd,8'hc2,8'hcb,8'hd0,8'hd9,8'hae,8'ha7,8'hbc,8'hb5,8'h8a,8'h83,8'h98,8'h91, 8'h4d,8'h44,8'h5f,8'h56,8'h69,8'h60,8'h7b,8'h72,8'h05,8'h0c,8'h17,8'h1e,8'h21,8'h28,8'h33,8'h3a, 8'hdd,8'hd4,8'hcf,8'hc6,8'hf9,8'hf0,8'heb,8'he2,8'h95,8'h9c,8'h87,8'h8e,8'hb1,8'hb8,8'ha3,8'haa, 8'hec,8'he5,8'hfe,8'hf7,8'hc8,8'hc1,8'hda,8'hd3,8'ha4,8'had,8'hb6,8'hbf,8'h80,8'h89,8'h92,8'h9b, 8'h7c,8'h75,8'h6e,8'h67,8'h58,8'h51,8'h4a,8'h43,8'h34,8'h3d,8'h26,8'h2f,8'h10,8'h19,8'h02,8'h0b, 8'hd7,8'hde,8'hc5,8'hcc,8'hf3,8'hfa,8'he1,8'he8,8'h9f,8'h96,8'h8d,8'h84,8'hbb,8'hb2,8'ha9,8'ha0, 8'h47,8'h4e,8'h55,8'h5c,8'h63,8'h6a,8'h71,8'h78,8'h0f,8'h06,8'h1d,8'h14,8'h2b,8'h22,8'h39,8'h30, 8'h9a,8'h93,8'h88,8'h81,8'hbe,8'hb7,8'hac,8'ha5,8'hd2,8'hdb,8'hc0,8'hc9,8'hf6,8'hff,8'he4,8'hed, 8'h0a,8'h03,8'h18,8'h11,8'h2e,8'h27,8'h3c,8'h35,8'h42,8'h4b,8'h50,8'h59,8'h66,8'h6f,8'h74,8'h7d, 8'ha1,8'ha8,8'hb3,8'hba,8'h85,8'h8c,8'h97,8'h9e,8'he9,8'he0,8'hfb,8'hf2,8'hcd,8'hc4,8'hdf,8'hd6, 8'h31,8'h38,8'h23,8'h2a,8'h15,8'h1c,8'h07,8'h0e,8'h79,8'h70,8'h6b,8'h62,8'h5d,8'h54,8'h4f,8'h46};
	reg [2047:0] galoisM11 = {8'h00,8'h0b,8'h16,8'h1d,8'h2c,8'h27,8'h3a,8'h31,8'h58,8'h53,8'h4e,8'h45,8'h74,8'h7f,8'h62,8'h69, 8'hb0,8'hbb,8'ha6,8'had,8'h9c,8'h97,8'h8a,8'h81,8'he8,8'he3,8'hfe,8'hf5,8'hc4,8'hcf,8'hd2,8'hd9, 8'h7b,8'h70,8'h6d,8'h66,8'h57,8'h5c,8'h41,8'h4a,8'h23,8'h28,8'h35,8'h3e,8'h0f,8'h04,8'h19,8'h12, 8'hcb,8'hc0,8'hdd,8'hd6,8'he7,8'hec,8'hf1,8'hfa,8'h93,8'h98,8'h85,8'h8e,8'hbf,8'hb4,8'ha9,8'ha2, 8'hf6,8'hfd,8'he0,8'heb,8'hda,8'hd1,8'hcc,8'hc7,8'hae,8'ha5,8'hb8,8'hb3,8'h82,8'h89,8'h94,8'h9f, 8'h46,8'h4d,8'h50,8'h5b,8'h6a,8'h61,8'h7c,8'h77,8'h1e,8'h15,8'h08,8'h03,8'h32,8'h39,8'h24,8'h2f, 8'h8d,8'h86,8'h9b,8'h90,8'ha1,8'haa,8'hb7,8'hbc,8'hd5,8'hde,8'hc3,8'hc8,8'hf9,8'hf2,8'hef,8'he4, 8'h3d,8'h36,8'h2b,8'h20,8'h11,8'h1a,8'h07,8'h0c,8'h65,8'h6e,8'h73,8'h78,8'h49,8'h42,8'h5f,8'h54, 8'hf7,8'hfc,8'he1,8'hea,8'hdb,8'hd0,8'hcd,8'hc6,8'haf,8'ha4,8'hb9,8'hb2,8'h83,8'h88,8'h95,8'h9e, 8'h47,8'h4c,8'h51,8'h5a,8'h6b,8'h60,8'h7d,8'h76,8'h1f,8'h14,8'h09,8'h02,8'h33,8'h38,8'h25,8'h2e, 8'h8c,8'h87,8'h9a,8'h91,8'ha0,8'hab,8'hb6,8'hbd,8'hd4,8'hdf,8'hc2,8'hc9,8'hf8,8'hf3,8'hee,8'he5, 8'h3c,8'h37,8'h2a,8'h21,8'h10,8'h1b,8'h06,8'h0d,8'h64,8'h6f,8'h72,8'h79,8'h48,8'h43,8'h5e,8'h55, 8'h01,8'h0a,8'h17,8'h1c,8'h2d,8'h26,8'h3b,8'h30,8'h59,8'h52,8'h4f,8'h44,8'h75,8'h7e,8'h63,8'h68, 8'hb1,8'hba,8'ha7,8'hac,8'h9d,8'h96,8'h8b,8'h80,8'he9,8'he2,8'hff,8'hf4,8'hc5,8'hce,8'hd3,8'hd8, 8'h7a,8'h71,8'h6c,8'h67,8'h56,8'h5d,8'h40,8'h4b,8'h22,8'h29,8'h34,8'h3f,8'h0e,8'h05,8'h18,8'h13, 8'hca,8'hc1,8'hdc,8'hd7,8'he6,8'hed,8'hf0,8'hfb,8'h92,8'h99,8'h84,8'h8f,8'hbe,8'hb5,8'ha8,8'ha3};
	reg [2047:0] galoisM13 = {8'h00,8'h0d,8'h1a,8'h17,8'h34,8'h39,8'h2e,8'h23,8'h68,8'h65,8'h72,8'h7f,8'h5c,8'h51,8'h46,8'h4b, 8'hd0,8'hdd,8'hca,8'hc7,8'he4,8'he9,8'hfe,8'hf3,8'hb8,8'hb5,8'ha2,8'haf,8'h8c,8'h81,8'h96,8'h9b, 8'hbb,8'hb6,8'ha1,8'hac,8'h8f,8'h82,8'h95,8'h98,8'hd3,8'hde,8'hc9,8'hc4,8'he7,8'hea,8'hfd,8'hf0, 8'h6b,8'h66,8'h71,8'h7c,8'h5f,8'h52,8'h45,8'h48,8'h03,8'h0e,8'h19,8'h14,8'h37,8'h3a,8'h2d,8'h20, 8'h6d,8'h60,8'h77,8'h7a,8'h59,8'h54,8'h43,8'h4e,8'h05,8'h08,8'h1f,8'h12,8'h31,8'h3c,8'h2b,8'h26, 8'hbd,8'hb0,8'ha7,8'haa,8'h89,8'h84,8'h93,8'h9e,8'hd5,8'hd8,8'hcf,8'hc2,8'he1,8'hec,8'hfb,8'hf6, 8'hd6,8'hdb,8'hcc,8'hc1,8'he2,8'hef,8'hf8,8'hf5,8'hbe,8'hb3,8'ha4,8'ha9,8'h8a,8'h87,8'h90,8'h9d, 8'h06,8'h0b,8'h1c,8'h11,8'h32,8'h3f,8'h28,8'h25,8'h6e,8'h63,8'h74,8'h79,8'h5a,8'h57,8'h40,8'h4d, 8'hda,8'hd7,8'hc0,8'hcd,8'hee,8'he3,8'hf4,8'hf9,8'hb2,8'hbf,8'ha8,8'ha5,8'h86,8'h8b,8'h9c,8'h91, 8'h0a,8'h07,8'h10,8'h1d,8'h3e,8'h33,8'h24,8'h29,8'h62,8'h6f,8'h78,8'h75,8'h56,8'h5b,8'h4c,8'h41, 8'h61,8'h6c,8'h7b,8'h76,8'h55,8'h58,8'h4f,8'h42,8'h09,8'h04,8'h13,8'h1e,8'h3d,8'h30,8'h27,8'h2a, 8'hb1,8'hbc,8'hab,8'ha6,8'h85,8'h88,8'h9f,8'h92,8'hd9,8'hd4,8'hc3,8'hce,8'hed,8'he0,8'hf7,8'hfa, 8'hb7,8'hba,8'had,8'ha0,8'h83,8'h8e,8'h99,8'h94,8'hdf,8'hd2,8'hc5,8'hc8,8'heb,8'he6,8'hf1,8'hfc, 8'h67,8'h6a,8'h7d,8'h70,8'h53,8'h5e,8'h49,8'h44,8'h0f,8'h02,8'h15,8'h18,8'h3b,8'h36,8'h21,8'h2c, 8'h0c,8'h01,8'h16,8'h1b,8'h38,8'h35,8'h22,8'h2f,8'h64,8'h69,8'h7e,8'h73,8'h50,8'h5d,8'h4a,8'h47, 8'hdc,8'hd1,8'hc6,8'hcb,8'he8,8'he5,8'hf2,8'hff,8'hb4,8'hb9,8'hae,8'ha3,8'h80,8'h8d,8'h9a,8'h97};
	reg [2047:0] galoisM14 = {8'h00,8'h0e,8'h1c,8'h12,8'h38,8'h36,8'h24,8'h2a,8'h70,8'h7e,8'h6c,8'h62,8'h48,8'h46,8'h54,8'h5a, 8'he0,8'hee,8'hfc,8'hf2,8'hd8,8'hd6,8'hc4,8'hca,8'h90,8'h9e,8'h8c,8'h82,8'ha8,8'ha6,8'hb4,8'hba, 8'hdb,8'hd5,8'hc7,8'hc9,8'he3,8'hed,8'hff,8'hf1,8'hab,8'ha5,8'hb7,8'hb9,8'h93,8'h9d,8'h8f,8'h81, 8'h3b,8'h35,8'h27,8'h29,8'h03,8'h0d,8'h1f,8'h11,8'h4b,8'h45,8'h57,8'h59,8'h73,8'h7d,8'h6f,8'h61, 8'had,8'ha3,8'hb1,8'hbf,8'h95,8'h9b,8'h89,8'h87,8'hdd,8'hd3,8'hc1,8'hcf,8'he5,8'heb,8'hf9,8'hf7, 8'h4d,8'h43,8'h51,8'h5f,8'h75,8'h7b,8'h69,8'h67,8'h3d,8'h33,8'h21,8'h2f,8'h05,8'h0b,8'h19,8'h17, 8'h76,8'h78,8'h6a,8'h64,8'h4e,8'h40,8'h52,8'h5c,8'h06,8'h08,8'h1a,8'h14,8'h3e,8'h30,8'h22,8'h2c, 8'h96,8'h98,8'h8a,8'h84,8'hae,8'ha0,8'hb2,8'hbc,8'he6,8'he8,8'hfa,8'hf4,8'hde,8'hd0,8'hc2,8'hcc, 8'h41,8'h4f,8'h5d,8'h53,8'h79,8'h77,8'h65,8'h6b,8'h31,8'h3f,8'h2d,8'h23,8'h09,8'h07,8'h15,8'h1b, 8'ha1,8'haf,8'hbd,8'hb3,8'h99,8'h97,8'h85,8'h8b,8'hd1,8'hdf,8'hcd,8'hc3,8'he9,8'he7,8'hf5,8'hfb, 8'h9a,8'h94,8'h86,8'h88,8'ha2,8'hac,8'hbe,8'hb0,8'hea,8'he4,8'hf6,8'hf8,8'hd2,8'hdc,8'hce,8'hc0, 8'h7a,8'h74,8'h66,8'h68,8'h42,8'h4c,8'h5e,8'h50,8'h0a,8'h04,8'h16,8'h18,8'h32,8'h3c,8'h2e,8'h20, 8'hec,8'he2,8'hf0,8'hfe,8'hd4,8'hda,8'hc8,8'hc6,8'h9c,8'h92,8'h80,8'h8e,8'ha4,8'haa,8'hb8,8'hb6, 8'h0c,8'h02,8'h10,8'h1e,8'h34,8'h3a,8'h28,8'h26,8'h7c,8'h72,8'h60,8'h6e,8'h44,8'h4a,8'h58,8'h56, 8'h37,8'h39,8'h2b,8'h25,8'h0f,8'h01,8'h13,8'h1d,8'h47,8'h49,8'h5b,8'h55,8'h7f,8'h71,8'h63,8'h6d, 8'hd7,8'hd9,8'hcb,8'hc5,8'hef,8'he1,8'hf3,8'hfd,8'ha7,8'ha9,8'hbb,8'hb5,8'h9f,8'h91,8'h83,8'h8d};

	assign aNew[127:120] = galoisM14[a[127:120]] ^ galoisM11[a[119:112]] ^ galoisM13[a[111:104]] ^ galoisM9[a[103:96]];
	assign aNew[119:112] = galoisM9[a[127:120]] ^ galoisM14[a[119:112]] ^ galoisM11[a[111:104]] ^ galoisM13[a[103:96]];
	assign aNew[111:104] = galoisM13[a[127:120]] ^ galoisM9[a[119:112]] ^ galoisM14[a[111:104]] ^ galoisM11[a[103:96]];
	assign aNew[103:96] = galoisM11[a[127:120]] ^ galoisM13[a[119:112]] ^ galoisM9[a[111:104]] ^ galoisM14[a[103:96]];

	assign aNew[95:88] = galoisM14[a[95:88]] ^ galoisM11[a[87:80]] ^ galoisM13[a[79:72]] ^ galoisM9[a[71:64]];
	assign aNew[87:80] = galoisM9[a[95:88]] ^ galoisM14[a[87:80]] ^ galoisM11[a[79:72]] ^ galoisM13[a[71:64]];
	assign aNew[79:72] = galoisM13[a[95:88]] ^ galoisM9[a[87:80]] ^ galoisM14[a[79:72]] ^ galoisM11[a[71:64]];
	assign aNew[71:64] = galoisM11[a[95:88]] ^ galoisM13[a[87:80]] ^ galoisM9[a[79:72]] ^ galoisM14[a[71:64]];

	assign aNew[63:56] = galoisM14[a[63:56]] ^ galoisM11[a[55:48]] ^ galoisM13[a[47:40]] ^ galoisM9[a[39:32]];
	assign aNew[55:48] = galoisM9[a[63:56]] ^ galoisM14[a[55:48]] ^ galoisM11[a[47:40]] ^ galoisM13[a[39:32]];
	assign aNew[47:40] = galoisM13[a[63:56]] ^ galoisM9[a[55:48]] ^ galoisM14[a[47:40]] ^ galoisM11[a[39:32]];
	assign aNew[39:32] = galoisM11[a[63:56]] ^ galoisM13[a[55:48]] ^ galoisM9[a[47:40]] ^ galoisM14[a[39:32]]; 

	assign aNew[31:24] = galoisM14[a[31:24]] ^ galoisM11[a[23:16]] ^galoisM13[a[15:8]] ^ galoisM9[a[7:0]];
	assign aNew[23:16] = galoisM9[a[31:24]] ^ galoisM14[a[23:16]] ^ galoisM11[a[15:8]] ^ galoisM13[a[7:0]];
	assign aNew[15:8] = galoisM13[a[31:24]] ^ galoisM9[a[23:16]] ^ galoisM14[a[15:8]] ^ galoisM11[a[7:0]];
	assign aNew[7:0] = galoisM11[a[31:24]] ^ galoisM13[a[23:16]] ^ galoisM9[a[15:8]] ^ galoisM14[a[7:0]];
endmodule


// XORRoundKey performed inside round and roundLast modules so no separate module for it


// procedure for round 1 to 9
module round(outRound, outKey, data, inKey, roundNum);
	output [127:0] outRound, outKey;
	input [127:0] inKey, data;
	input [3:0] roundNum;

	wire [127:0] sub, shifted, mixed;
	
	getRoundKeys g1(.outKey(outKey), .inKey(inKey), .roundNum(roundNum));
	subBytes sb1(.sub(sub), .data(data));
	shiftRow sr1(.shifted(shifted), .data(sub));
	mixColumns mc1(.aNew(mixed), .a(shifted));

	assign outRound = outKey ^ mixed;
endmodule


module inv_round(outRound, data, rKey);
	output [127:0] outRound;
	input [127:0] rKey, data;

	//wire [127:0] XORRound, inv_mixed, inv_shifted; //bug???
	wire [127:0] XORRoundKey, inv_mixed, inv_shifted;
	
	assign XORRoundKey = rKey ^ data;
	inv_mixColumns imc1(.aNew(inv_mixed), .a(XORRoundKey));
	inv_shiftRow isr1(.data(inv_shifted), .shifted(inv_mixed));
	inv_subBytes isb1(.sub(outRound), .data(inv_shifted));
endmodule


// procedure for round 10
module roundLast(encryptedData, data, inKey, roundNum);
	output [127:0] encryptedData;
	input [127:0] data, inKey;
	input [3:0] roundNum;

	wire [127:0] sub, shifted, outKey;
	
	getRoundKeys g1(.outKey(outKey), .inKey(inKey), .roundNum(roundNum));
	subBytes sb1(.sub(sub), .data(data));
	shiftRow sr1(.shifted(shifted), .data(sub));

	assign encryptedData = outKey ^ shifted;
endmodule


module inv_roundLast(data, encryptedData, rKey);
	output [127:0] data;
	input [127:0] encryptedData, rKey;

	//wire [127:0] XORRound, inv_shifted; // bug???
	wire [127:0] XORRoundKey, inv_shifted;
	
	assign XORRoundKey = rKey ^ encryptedData;
	inv_shiftRow sr1(.data(inv_shifted), .shifted(XORRoundKey));
	inv_subBytes sb1(.sub(data), .data(inv_shifted));
endmodule


// substitution mappings
module sbox(sub, toReplace);
	output [7:0] sub;
	input [7:0] toReplace;

	reg [7:0] sub;

	always @(toReplace)
		case (toReplace)
			8'h00: sub=8'h63;
	   		8'h01: sub=8'h7c;
	   		8'h02: sub=8'h77;
	   		8'h03: sub=8'h7b;
	   		8'h04: sub=8'hf2;
	   		8'h05: sub=8'h6b;
	   		8'h06: sub=8'h6f;
	   		8'h07: sub=8'hc5;
	   		8'h08: sub=8'h30;
	   		8'h09: sub=8'h01;
	   		8'h0a: sub=8'h67;
	   		8'h0b: sub=8'h2b;
	   		8'h0c: sub=8'hfe;
	   		8'h0d: sub=8'hd7;
	   		8'h0e: sub=8'hab;
	   		8'h0f: sub=8'h76;
	   		8'h10: sub=8'hca;
	   		8'h11: sub=8'h82;
	   		8'h12: sub=8'hc9;
	   		8'h13: sub=8'h7d;
	   		8'h14: sub=8'hfa;
	   		8'h15: sub=8'h59;
	   		8'h16: sub=8'h47;
	   		8'h17: sub=8'hf0;
	   		8'h18: sub=8'had;
	   		8'h19: sub=8'hd4;
	   		8'h1a: sub=8'ha2;
	   		8'h1b: sub=8'haf;
	   		8'h1c: sub=8'h9c;
	   		8'h1d: sub=8'ha4;
	   		8'h1e: sub=8'h72;
	   		8'h1f: sub=8'hc0;
	   		8'h20: sub=8'hb7;
	   		8'h21: sub=8'hfd;
	   		8'h22: sub=8'h93;
	   		8'h23: sub=8'h26;
	   		8'h24: sub=8'h36;
	   		8'h25: sub=8'h3f;
	   		8'h26: sub=8'hf7;
	   		8'h27: sub=8'hcc;
	   		8'h28: sub=8'h34;
	   		8'h29: sub=8'ha5;
	   		8'h2a: sub=8'he5;
	   		8'h2b: sub=8'hf1;
	   		8'h2c: sub=8'h71;
	   		8'h2d: sub=8'hd8;
	   		8'h2e: sub=8'h31;
	   		8'h2f: sub=8'h15;
	   		8'h30: sub=8'h04;
	   		8'h31: sub=8'hc7;
	   		8'h32: sub=8'h23;
	   		8'h33: sub=8'hc3;
	   		8'h34: sub=8'h18;
	   		8'h35: sub=8'h96;
	   		8'h36: sub=8'h05;
	   		8'h37: sub=8'h9a;
	   		8'h38: sub=8'h07;
	   		8'h39: sub=8'h12;
	   		8'h3a: sub=8'h80;
	   		8'h3b: sub=8'he2;
	   		8'h3c: sub=8'heb;
	   		8'h3d: sub=8'h27;
	   		8'h3e: sub=8'hb2;
	   		8'h3f: sub=8'h75;
	   		8'h40: sub=8'h09;
	   		8'h41: sub=8'h83;
	   		8'h42: sub=8'h2c;
	   		8'h43: sub=8'h1a;
	   		8'h44: sub=8'h1b;
	   		8'h45: sub=8'h6e;
	   		8'h46: sub=8'h5a;
	   		8'h47: sub=8'ha0;
	   		8'h48: sub=8'h52;
	   		8'h49: sub=8'h3b;
	   		8'h4a: sub=8'hd6;
	   		8'h4b: sub=8'hb3;
	   		8'h4c: sub=8'h29;
	   		8'h4d: sub=8'he3;
	   		8'h4e: sub=8'h2f;
	   		8'h4f: sub=8'h84;
	   		8'h50: sub=8'h53;
	   		8'h51: sub=8'hd1;
	   		8'h52: sub=8'h00;
	   		8'h53: sub=8'hed;
	   		8'h54: sub=8'h20;
	   		8'h55: sub=8'hfc;
	   		8'h56: sub=8'hb1;
	   		8'h57: sub=8'h5b;
	   		8'h58: sub=8'h6a;
	   		8'h59: sub=8'hcb;
	   		8'h5a: sub=8'hbe;
	   		8'h5b: sub=8'h39;
	   		8'h5c: sub=8'h4a;
	   		8'h5d: sub=8'h4c;
	   		8'h5e: sub=8'h58;
	   		8'h5f: sub=8'hcf;
	   		8'h60: sub=8'hd0;
	   		8'h61: sub=8'hef;
	   		8'h62: sub=8'haa;
	   		8'h63: sub=8'hfb;
	   		8'h64: sub=8'h43;
	  		8'h65: sub=8'h4d;
	   		8'h66: sub=8'h33;
	   		8'h67: sub=8'h85;
	   		8'h68: sub=8'h45;
	   		8'h69: sub=8'hf9;
	   		8'h6a: sub=8'h02;
	   		8'h6b: sub=8'h7f;
	   		8'h6c: sub=8'h50;
	   		8'h6d: sub=8'h3c;
	   		8'h6e: sub=8'h9f;
	   		8'h6f: sub=8'ha8;
	   		8'h70: sub=8'h51;
	   		8'h71: sub=8'ha3;
	   		8'h72: sub=8'h40;
	   		8'h73: sub=8'h8f;
	   		8'h74: sub=8'h92;
	   		8'h75: sub=8'h9d;
	   		8'h76: sub=8'h38;
	   		8'h77: sub=8'hf5;
	   		8'h78: sub=8'hbc;
	   		8'h79: sub=8'hb6;
	   		8'h7a: sub=8'hda;
	   		8'h7b: sub=8'h21;
	   		8'h7c: sub=8'h10;
	   		8'h7d: sub=8'hff;
	   		8'h7e: sub=8'hf3;
	   		8'h7f: sub=8'hd2;
	   		8'h80: sub=8'hcd;
	   		8'h81: sub=8'h0c;
	   		8'h82: sub=8'h13;
	   		8'h83: sub=8'hec;
	   		8'h84: sub=8'h5f;
	   		8'h85: sub=8'h97;
	   		8'h86: sub=8'h44;
	   		8'h87: sub=8'h17;
	   		8'h88: sub=8'hc4;
	   		8'h89: sub=8'ha7;
	   		8'h8a: sub=8'h7e;
	   		8'h8b: sub=8'h3d;
	   		8'h8c: sub=8'h64;
	   		8'h8d: sub=8'h5d;
	   		8'h8e: sub=8'h19;
	   		8'h8f: sub=8'h73;
	   		8'h90: sub=8'h60;
	   		8'h91: sub=8'h81;
	   		8'h92: sub=8'h4f;
	   		8'h93: sub=8'hdc;
	   		8'h94: sub=8'h22;
	   		8'h95: sub=8'h2a;
	   		8'h96: sub=8'h90;
	   		8'h97: sub=8'h88;
	   		8'h98: sub=8'h46;
	   		8'h99: sub=8'hee;
	   		8'h9a: sub=8'hb8;
	   		8'h9b: sub=8'h14;
	   		8'h9c: sub=8'hde;
	   		8'h9d: sub=8'h5e;
	   		8'h9e: sub=8'h0b;
	   		8'h9f: sub=8'hdb;
	   		8'ha0: sub=8'he0;
	   		8'ha1: sub=8'h32;
	   		8'ha2: sub=8'h3a;
	   		8'ha3: sub=8'h0a;
	   		8'ha4: sub=8'h49;
	   		8'ha5: sub=8'h06;
	   		8'ha6: sub=8'h24;
	   		8'ha7: sub=8'h5c;
	   		8'ha8: sub=8'hc2;
	   		8'ha9: sub=8'hd3;
	   		8'haa: sub=8'hac;
	   		8'hab: sub=8'h62;
	   		8'hac: sub=8'h91;
	   		8'had: sub=8'h95;
	   		8'hae: sub=8'he4;
	   		8'haf: sub=8'h79;
	   		8'hb0: sub=8'he7;
	   		8'hb1: sub=8'hc8;
	   		8'hb2: sub=8'h37;
	   		8'hb3: sub=8'h6d;
	   		8'hb4: sub=8'h8d;
	   		8'hb5: sub=8'hd5;
	   		8'hb6: sub=8'h4e;
	   		8'hb7: sub=8'ha9;
	   		8'hb8: sub=8'h6c;
	   		8'hb9: sub=8'h56;
	   		8'hba: sub=8'hf4;
	   		8'hbb: sub=8'hea;
	   		8'hbc: sub=8'h65;
	   		8'hbd: sub=8'h7a;
	   		8'hbe: sub=8'hae;
	   		8'hbf: sub=8'h08;
	   		8'hc0: sub=8'hba;
	   		8'hc1: sub=8'h78;
	   		8'hc2: sub=8'h25;
	   		8'hc3: sub=8'h2e;
	   		8'hc4: sub=8'h1c;
	   		8'hc5: sub=8'ha6;
	   		8'hc6: sub=8'hb4;
	   		8'hc7: sub=8'hc6;
	   		8'hc8: sub=8'he8;
	   		8'hc9: sub=8'hdd;
	   		8'hca: sub=8'h74;
	   		8'hcb: sub=8'h1f;
	   		8'hcc: sub=8'h4b;
	   		8'hcd: sub=8'hbd;
	   		8'hce: sub=8'h8b;
	   		8'hcf: sub=8'h8a;
	   		8'hd0: sub=8'h70;
	   		8'hd1: sub=8'h3e;
	   		8'hd2: sub=8'hb5;
	   		8'hd3: sub=8'h66;
	   		8'hd4: sub=8'h48;
	   		8'hd5: sub=8'h03;
	   		8'hd6: sub=8'hf6;
	   		8'hd7: sub=8'h0e;
	   		8'hd8: sub=8'h61;
	   		8'hd9: sub=8'h35;
	   		8'hda: sub=8'h57;
	   		8'hdb: sub=8'hb9;
	   		8'hdc: sub=8'h86;
	   		8'hdd: sub=8'hc1;
	   		8'hde: sub=8'h1d;
	   		8'hdf: sub=8'h9e;
	   		8'he0: sub=8'he1;
	   		8'he1: sub=8'hf8;
	   		8'he2: sub=8'h98;
	   		8'he3: sub=8'h11;
	   		8'he4: sub=8'h69;
	   		8'he5: sub=8'hd9;
	   		8'he6: sub=8'h8e;
	   		8'he7: sub=8'h94;
	   		8'he8: sub=8'h9b;
	   		8'he9: sub=8'h1e;
	   		8'hea: sub=8'h87;
	   		8'heb: sub=8'he9;
	   		8'hec: sub=8'hce;
	   		8'hed: sub=8'h55;
	   		8'hee: sub=8'h28;
	   		8'hef: sub=8'hdf;
	   		8'hf0: sub=8'h8c;
	   		8'hf1: sub=8'ha1;
	   		8'hf2: sub=8'h89;
	   		8'hf3: sub=8'h0d;
	   		8'hf4: sub=8'hbf;
	   		8'hf5: sub=8'he6;
	   		8'hf6: sub=8'h42;
	   		8'hf7: sub=8'h68;
	   		8'hf8: sub=8'h41;
	   		8'hf9: sub=8'h99;
	   		8'hfa: sub=8'h2d;
	   		8'hfb: sub=8'h0f;
	   		8'hfc: sub=8'hb0;
	   		8'hfd: sub=8'h54;
	   		8'hfe: sub=8'hbb;
	   		8'hff: sub=8'h16;
		endcase
endmodule


// inverse substitution mappings
module inv_sbox(sub, toReplace);
	output [7:0] sub;
	input [7:0] toReplace;

	reg [7:0] sub;

	always @(toReplace)
		case (toReplace)
			8'h00: sub=8'h52;
			8'h01: sub=8'h09;
			8'h02: sub=8'h6a;
			8'h03: sub=8'hd5;
			8'h04: sub=8'h30;
			8'h05: sub=8'h36;
			8'h06: sub=8'ha5;
			8'h07: sub=8'h38;
			8'h08: sub=8'hbf;
			8'h09: sub=8'h40;
			8'h0a: sub=8'ha3;
			8'h0b: sub=8'h9e;
			8'h0c: sub=8'h81;
			8'h0d: sub=8'hf3;
			8'h0e: sub=8'hd7;
			8'h0f: sub=8'hfb;
			8'h10: sub=8'h7c;
			8'h11: sub=8'he3;
			8'h12: sub=8'h39;
			8'h13: sub=8'h82;
			8'h14: sub=8'h9b;
			8'h15: sub=8'h2f;
			8'h16: sub=8'hff;
			8'h17: sub=8'h87;
			8'h18: sub=8'h34;
			8'h19: sub=8'h8e;
			8'h1a: sub=8'h43;
			8'h1b: sub=8'h44;
			8'h1c: sub=8'hc4;
			8'h1d: sub=8'hde;
			8'h1e: sub=8'he9;
			8'h1f: sub=8'hcb;
			8'h20: sub=8'h54;
			8'h21: sub=8'h7b;
			8'h22: sub=8'h94;
			8'h23: sub=8'h32;
			8'h24: sub=8'ha6;
			8'h25: sub=8'hc2;
			8'h26: sub=8'h23;
			8'h27: sub=8'h3d;
			8'h28: sub=8'hee;
			8'h29: sub=8'h4c;
			8'h2a: sub=8'h95;
			8'h2b: sub=8'h0b;
			8'h2c: sub=8'h42;
			8'h2d: sub=8'hfa;
			8'h2e: sub=8'hc3;
			8'h2f: sub=8'h4e;
			8'h30: sub=8'h08;
			8'h31: sub=8'h2e;
			8'h32: sub=8'ha1;
			8'h33: sub=8'h66;
			8'h34: sub=8'h28;
			8'h35: sub=8'hd9;
			8'h36: sub=8'h24;
			8'h37: sub=8'hb2;
			8'h38: sub=8'h76;
			8'h39: sub=8'h5b;
			8'h3a: sub=8'ha2;
			8'h3b: sub=8'h49;
			8'h3c: sub=8'h6d;
			8'h3d: sub=8'h8b;
			8'h3e: sub=8'hd1;
			8'h3f: sub=8'h25;
			8'h40: sub=8'h72;
			8'h41: sub=8'hf8;
			8'h42: sub=8'hf6;
			8'h43: sub=8'h64;
			8'h44: sub=8'h86;
			8'h45: sub=8'h68;
			8'h46: sub=8'h98;
			8'h47: sub=8'h16;
			8'h48: sub=8'hd4;
			8'h49: sub=8'ha4;
			8'h4a: sub=8'h5c;
			8'h4b: sub=8'hcc;
			8'h4c: sub=8'h5d;
			8'h4d: sub=8'h65;
			8'h4e: sub=8'hb6;
			8'h4f: sub=8'h92;
			8'h50: sub=8'h6c;
			8'h51: sub=8'h70;
			8'h52: sub=8'h48;
			8'h53: sub=8'h50;
			8'h54: sub=8'hfd;
			8'h55: sub=8'hed;
			8'h56: sub=8'hb9;
			8'h57: sub=8'hda;
			8'h58: sub=8'h5e;
			8'h59: sub=8'h15;
			8'h5a: sub=8'h46;
			8'h5b: sub=8'h57;
			8'h5c: sub=8'ha7;
			8'h5d: sub=8'h8d;
			8'h5e: sub=8'h9d;
			8'h5f: sub=8'h84;
			8'h60: sub=8'h90;
			8'h61: sub=8'hd8;
			8'h62: sub=8'hab;
			8'h63: sub=8'h00;
			8'h64: sub=8'h8c;
			8'h65: sub=8'hbc;
			8'h66: sub=8'hd3;
			8'h67: sub=8'h0a;
			8'h68: sub=8'hf7;
			8'h69: sub=8'he4;
			8'h6a: sub=8'h58;
			8'h6b: sub=8'h05;
			8'h6c: sub=8'hb8;
			8'h6d: sub=8'hb3;
			8'h6e: sub=8'h45;
			8'h6f: sub=8'h06;
			8'h70: sub=8'hd0;
			8'h71: sub=8'h2c;
			8'h72: sub=8'h1e;
			8'h73: sub=8'h8f;
			8'h74: sub=8'hca;
			8'h75: sub=8'h3f;
			8'h76: sub=8'h0f;
			8'h77: sub=8'h02;
			8'h78: sub=8'hc1;
			8'h79: sub=8'haf;
			8'h7a: sub=8'hbd;
			8'h7b: sub=8'h03;
			8'h7c: sub=8'h01;
			8'h7d: sub=8'h13;
			8'h7e: sub=8'h8a;
			8'h7f: sub=8'h6b;
			8'h80: sub=8'h3a;
			8'h81: sub=8'h91;
			8'h82: sub=8'h11;
			8'h83: sub=8'h41;
			8'h84: sub=8'h4f;
			8'h85: sub=8'h67;
			8'h86: sub=8'hdc;
			8'h87: sub=8'hea;
			8'h88: sub=8'h97;
			8'h89: sub=8'hf2;
			8'h8a: sub=8'hcf;
			8'h8b: sub=8'hce;
			8'h8c: sub=8'hf0;
			8'h8d: sub=8'hb4;
			8'h8e: sub=8'he6;
			8'h8f: sub=8'h73;
			8'h90: sub=8'h96;
			8'h91: sub=8'hac;
			8'h92: sub=8'h74;
			8'h93: sub=8'h22;
			8'h94: sub=8'he7;
			8'h95: sub=8'had;
			8'h96: sub=8'h35;
			8'h97: sub=8'h85;
			8'h98: sub=8'he2;
			8'h99: sub=8'hf9;
			8'h9a: sub=8'h37;
			8'h9b: sub=8'he8;
			8'h9c: sub=8'h1c;
			8'h9d: sub=8'h75;
			8'h9e: sub=8'hdf;
			8'h9f: sub=8'h6e;
			8'ha0: sub=8'h47;
			8'ha1: sub=8'hf1;
			8'ha2: sub=8'h1a;
			8'ha3: sub=8'h71;
			8'ha4: sub=8'h1d;
			8'ha5: sub=8'h29;
			8'ha6: sub=8'hc5;
			8'ha7: sub=8'h89;
			8'ha8: sub=8'h6f;
			8'ha9: sub=8'hb7;
			8'haa: sub=8'h62;
			8'hab: sub=8'h0e;
			8'hac: sub=8'haa;
			8'had: sub=8'h18;
			8'hae: sub=8'hbe;
			8'haf: sub=8'h1b;
			8'hb0: sub=8'hfc;
			8'hb1: sub=8'h56;
			8'hb2: sub=8'h3e;
			8'hb3: sub=8'h4b;
			8'hb4: sub=8'hc6;
			8'hb5: sub=8'hd2;
			8'hb6: sub=8'h79;
			8'hb7: sub=8'h20;
			8'hb8: sub=8'h9a;
			8'hb9: sub=8'hdb;
			8'hba: sub=8'hc0;
			8'hbb: sub=8'hfe;
			8'hbc: sub=8'h78;
			8'hbd: sub=8'hcd;
			8'hbe: sub=8'h5a;
			8'hbf: sub=8'hf4;
			8'hc0: sub=8'h1f;
			8'hc1: sub=8'hdd;
			8'hc2: sub=8'ha8;
			8'hc3: sub=8'h33;
			8'hc4: sub=8'h88;
			8'hc5: sub=8'h07;
			8'hc6: sub=8'hc7;
			8'hc7: sub=8'h31;
			8'hc8: sub=8'hb1;
			8'hc9: sub=8'h12;
			8'hca: sub=8'h10;
			8'hcb: sub=8'h59;
			8'hcc: sub=8'h27;
			8'hcd: sub=8'h80;
			8'hce: sub=8'hec;
			8'hcf: sub=8'h5f;
			8'hd0: sub=8'h60;
			8'hd1: sub=8'h51;
			8'hd2: sub=8'h7f;
			8'hd3: sub=8'ha9;
			8'hd4: sub=8'h19;
			8'hd5: sub=8'hb5;
			8'hd6: sub=8'h4a;
			8'hd7: sub=8'h0d;
			8'hd8: sub=8'h2d;
			8'hd9: sub=8'he5;
			8'hda: sub=8'h7a;
			8'hdb: sub=8'h9f;
			8'hdc: sub=8'h93;
			8'hdd: sub=8'hc9;
			8'hde: sub=8'h9c;
			8'hdf: sub=8'hef;
			8'he0: sub=8'ha0;
			8'he1: sub=8'he0;
			8'he2: sub=8'h3b;
			8'he3: sub=8'h4d;
			8'he4: sub=8'hae;
			8'he5: sub=8'h2a;
			8'he6: sub=8'hf5;
			8'he7: sub=8'hb0;
			8'he8: sub=8'hc8;
			8'he9: sub=8'heb;
			8'hea: sub=8'hbb;
			8'heb: sub=8'h3c;
			8'hec: sub=8'h83;
			8'hed: sub=8'h53;
			8'hee: sub=8'h99;
			8'hef: sub=8'h61;
			8'hf0: sub=8'h17;
			8'hf1: sub=8'h2b;
			8'hf2: sub=8'h04;
			8'hf3: sub=8'h7e;
			8'hf4: sub=8'hba;
			8'hf5: sub=8'h77;
			8'hf6: sub=8'hd6;
			8'hf7: sub=8'h26;
			8'hf8: sub=8'he1;
			8'hf9: sub=8'h69;
			8'hfa: sub=8'h14;
			8'hfb: sub=8'h63;
			8'hfc: sub=8'h55;
			8'hfd: sub=8'h21;
			8'hfe: sub=8'h0c;
			8'hff: sub=8'h7d;
		endcase
endmodule

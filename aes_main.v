// encrypts data using (transformed) master key that is available with admin
// gives output at each clock
module aes_encrypt(encryptedData, data, mKey, clk);
	output reg [127:0] encryptedData;
	input [127:0] data, mKey;
	input clk;

	wire [127:0] rOut0, rOut1, rOut2, rOut3, rOut4, rOut5, rOut6, rOut7, rOut8, rOut9, rOut10;
	wire [127:0] keyOut1, keyOut2, keyOut3, keyOut4, keyOut5, keyOut6, keyOut7, keyOut8, keyOut9;

	assign rOut0 = data ^ mKey;

    	round r1(.outKey(keyOut1), .outRound(rOut1), .roundNum(4'b0000), .data(rOut0), .inKey(mKey));
    	round r2(.outKey(keyOut2), .outRound(rOut2), .roundNum(4'b0001), .data(rOut1), .inKey(keyOut1));
    	round r3(.outKey(keyOut3), .outRound(rOut3), .roundNum(4'b0010), .data(rOut2), .inKey(keyOut2));
    	round r4(.outKey(keyOut4), .outRound(rOut4), .roundNum(4'b0011), .data(rOut3), .inKey(keyOut3));
    	round r5(.outKey(keyOut5), .outRound(rOut5), .roundNum(4'b0100), .data(rOut4), .inKey(keyOut4));
    	round r6(.outKey(keyOut6), .outRound(rOut6), .roundNum(4'b0101), .data(rOut5), .inKey(keyOut5));
    	round r7(.outKey(keyOut7), .outRound(rOut7), .roundNum(4'b0110), .data(rOut6), .inKey(keyOut6));
    	round r8(.outKey(keyOut8), .outRound(rOut8), .roundNum(4'b0111), .data(rOut7), .inKey(keyOut7));
    	round r9(.outKey(keyOut9), .outRound(rOut9), .roundNum(4'b1000), .data(rOut8), .inKey(keyOut8));
    	roundLast r10(.encryptedData(rOut10), .roundNum(4'b1001), .data(rOut9), .inKey(keyOut9));

	always @(posedge clk) begin
		encryptedData = rOut10;
	end
endmodule


// decrypts data, provided encrypted data and master key
// gives output at each clock
module aes_decrypt(decryptedData, encryptedData, mKey, clk);
	output reg [127:0] decryptedData;
	input [127:0] encryptedData, mKey;
	input clk;

	wire [1279:0] iRK;
	wire [127:0] iROut1, iROut2, iROut3, iROut4, iROut5, iROut6, iROut7, iROut8, iROut9, iROut10, finIR;

	getInvRoundKeys girk1(iRK, mKey);

	//inverse of round10 of encryption
   	inv_roundLast ir1(.data(iROut1), .encryptedData(encryptedData), .rKey(iRK[127:0]));
   	//inverse of round9 of encryption
	inv_round ir2(.outRound(iROut2), .data(iROut1), .rKey(iRK[255:128]));
	inv_round ir3(.outRound(iROut3), .data(iROut2), .rKey(iRK[383:256]));
	inv_round ir4(.outRound(iROut4), .data(iROut3), .rKey(iRK[511:384]));
	inv_round ir5(.outRound(iROut5), .data(iROut4), .rKey(iRK[639:512]));
	inv_round ir6(.outRound(iROut6), .data(iROut5), .rKey(iRK[767:640]));
	inv_round ir7(.outRound(iROut7), .data(iROut6), .rKey(iRK[895:768]));
	inv_round ir8(.outRound(iROut8), .data(iROut7), .rKey(iRK[1023:896]));
	inv_round ir9(.outRound(iROut9), .data(iROut8), .rKey(iRK[1151:1024]));
	inv_round ir10(.outRound(iROut10), .data(iROut9), .rKey(iRK[1279:1152]));
	
	assign finIR = iROut10 ^ mKey;

	always @(posedge clk) begin
		decryptedData = finIR;
	end
endmodule

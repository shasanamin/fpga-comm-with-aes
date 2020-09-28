// primary code author: Hasan Tariq

`timescale 1ns / 1ps
module UpperModule(input clock, input rst, input button, input switch,output txd, input rxd);
	reg transmits=0;

	// vector to encrypt
	wire [127:0] vec = 128'h 48656c6c6f2044722e20416465656c21;
	// key for AES encryption
	wire [127:0] key = 128'h 2b7e151628aed2a6abf7158809cf4f3c;

	reg [7:0] v = 8'h18;

	reg [7:0] sending;
	initial begin 
		sending = vec[7:0];
	end

	integer numTrans = 0;
	integer countBaud = 0;
	reg [127:0] sig;
	wire [127:0] converted;
	
	// transmitter integration into top level module. passing clock, reset,
	// data to be transmitted.

	Tx t1(
		.clk(clock), //UART input clock
		.reset(rstControl), // reset signal
		.transmit(transmits), //btn signal to trigger the UART communication
		.data(sig),
		.TxD(txd) // Transmitter serial output. TxD will be held high during reset, or when no transmissions are taking place. 
	);

	// perform encryption
	aes_encrypt newencrypt(.encryptedData(converted), .data(vec), .mKey(key), .clk(clock));

	wire [7:0] datout;
	wire rdyout;

	integer count=0;
	integer flag=0;

	// debouncing circuit
	always @ (posedge clock)
	begin		
		if(button)
		begin
			count=count+1;
			if (count >= 15000000)
			begin
				if(!flag) 
				begin
					transmits=1; 
					flag=1;
				end
			end
			if (count> 15005999)
			begin 
				transmits=0; 
			end
		end
			
		if(!button)
		begin
			flag=0;
			count=0;
			transmits=0;
		end
	end

	// state machine for selecting what to transmit
	always @ (switch)
	begin 
			if(switch)
				sig=converted;
			
			else
				sig=vec;
	end

	integer counter=0;

	// temp reg
	reg [127:0] data;
	// data input for sending forward
	reg [127:0] data_1;
endmodule

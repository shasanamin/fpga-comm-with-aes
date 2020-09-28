// primary code author: Hasan Tariq

`timescale 1ns / 1ps
module UpperModule(input clock, input rst, input button, input switch,output txd, input rxd);
	wire [127:0] vec = 128'h 48656c6c6f2044722e20416465656c21;
	wire [127:0] key = 128'h 2b7e151628aed2a6abf7158809cf4f3c;
	wire [127:0] converted;

	reg [7:0] v = 8'h18;
	reg transmits=0;
	reg [127:0] sig=59;
	reg [7:0] sending;
	
	integer numTrans = 0;
	integer countBaud = 0;

	initial begin 
		sending = vec[7:0];
	end

	Tx t1(
		.clk(clock), //UART input clock
		.reset(rstControl), // reset signal
		.transmit(transmits), //btn signal to trigger the UART communication
		//input [7:0] data, // data transmitted
		.data(sig),
		.TxD(txd) // Transmitter serial output. TxD will be held high during reset, or when no transmissions are taking place. 
	);

	wire [7:0] datout;
	wire rdy_out;
	
	Rx R1(
		.clk(clock), // UART input clock
		.rst(rstControl), // reset signal
		.data_out(datout), //data recieved
		.rdy_out(rdy_out),			// data is ready 
		.ser_in(rxd)		// recieve pin
	);	

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

	integer counter=0;

	reg [127:0] data; // temp reg
	reg [127:0] data_1; // data input for sending forward

	// implement a buffer to store
	always@ (posedge clock)
	begin					// all the values that were 
		if (rstControl)		// transmitted by the custom
		begin				// 128 bit transmitter
			counter =0;
			data_1 =0;
			data = 0;
		end
		else
		begin
			if(rdy_out)		// This signals that the data has
			begin			// has been recieved on the buffer.
				counter = counter +1;		 
				case (counter)					// Concatenate the data until we
												// we have a 128 bit chunk.
					16'd200:	begin 
									data[7:0] =  datout;
									data_1 = 0;
								end
					16'd400:	begin
									data [15:8] = datout;
									data_1 =0;
								end
					16'd600: 	begin 
									data [23:16] = datout;
									data_1 =0;
								end
					16'd800: 	begin
									data[31:24] = datout;
									data_1 =0;
								end
					16'd1000: 	begin
									data [39:32] = datout;
									data_1 =0;
								end
					16'd1200: 	begin
									data [47:40] = datout;
									data_1 =0;
								end
					16'd1400: 	begin
									data [55:48] = datout;
									data_1 =0;
								end
					16'd1600:	begin
									data [63:56] = datout;
									data_1 = data;
								end 
					16'd1800:	begin
									data [71:64] = datout;
									data_1 = data;
								end 
					16'd2000:	begin
									data [79:72] = datout;
									data_1 = data;
								end 
					16'd2200:	begin
									data [87:80] = datout;
									data_1 = data;
								end 
					16'd2400:	begin
									data [95:88] = datout;
									data_1 = data;
								end 								
					16'd2600:	begin
									data [103:96] = datout;
									data_1 = data;
								end 
					16'd2800:	begin
									data [111:104] = datout;
									data_1 = data;
								end 
					16'd3000:	begin
									data [119:112] = datout;
									data_1 = data;
								end 
					16'd3200:	begin							// should handle 
									data [127:120] = datout;	// trans and assign
									data_1 = data;				// to transmit signal
									sig = data_1;
									//data_1 = 0;
									//data = 0;
									//transmit=1;
								end 								
						
					default: 	begin
									counter = counter;
									data = data;
									data_1 = data_1;
								end						
				endcase		
			end
			else
				begin
					counter = counter;
					data = data;
					data_1 = data_1;
				end 
		end
	end
endmodule

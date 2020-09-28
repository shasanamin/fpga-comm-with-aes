# FPGA-based Secure Communication using Advanced Encryption Standard (AES)

This repository contains a hardware implementation of the AES encryption and decryption algorithms to be used as part of a secure and efficient UART-based FPGA-FPGA and/or FPGA-PC communication system. No IP cores were used --- resource utilization $<$ 3% percent on an entry-level FPGA development board (Basys 3).

AES is a symmetric key block cipher with block lengh of 128 bits used extensively to protect classified information. This implementation selects key length to be 128 bits too. [Avi Kak's notes](https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf) are an excellent resource to learn more about it.

Universal Asynchronous Receiver/Transmitter (UART)-based communication was selected due to its popularity and simplicity. Since AES requires 128-bit blocks for processing, UART transmitter is padded when necessary. Further, a buffer is implemented at receiver end to store data till one 128-bit block is completely received.

### Code explanation
#### Cryptography
(1) aes_main.v: Higher level modules for AES encryption and decryption.

(2) aes_utils.v: Lower level modules for AES encryption and decryption.

#### Communication
(3) encryption_node.v: Send data to another FPGA or PC, and/or encrypt it.

(4) intermediate_node.v: Send and/or receive data from another FPGA or PC.
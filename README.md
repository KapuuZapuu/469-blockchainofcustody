# 469 Project - CoC
This is the repository for the CSE 469 group 14
Ryan Leigh - 1224401633
Cameron Mendez - 121866937
Hassan Khan - 1225282448

Generative AI Acknowledgment: Portions of the code in this project were
generated with assistance from ChatGPT, an AI tool developed by OpenAI.
Reference: OpenAI. (2024). ChatGPT [Large language model].
openai.com/chatgpt

The chain of custody project centers around the the main function which uses an ArgumentParser to deliver a CLI interface for a user. Each potential keyword in the parser links to a function, such as add, remove, checkin, checkout. These functions manipulate the existing bin file for byte-representation to be stored or the provided file through environment commands. This file, in which we store the blockchain in a byte representaion. Inbetween writing and reading from the file, the data is packed or unpacked into a predetermined structure in order to have consistency in the spacing and padding of data, also to be knowledgeable of where each data is stored. Additionally, evidence and case IDs are encrypted using AES (ECB mode) with a fixed key. Through command line arguments role-based access is controlled via passwords stored in environment variables where each action may require some kind of authentication in order to occur.

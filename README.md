# Netwolf
A program that enables the users to transfer files via a P2P connection.

## Section 1 - Starting the program
to start the program, you have to simply enter the following command in the terminal:

`python Netwolf.py -f <file_name> -d <folder_name>`

Therefore, after -f, you have to enter the directory of a file that stores the nodes in the discovery section (we'll see it later on) in JSON format. After -d, you need to enter the folder directory that keeps files that we transfer via TCP.

\* **Note that these arguments are optional, and if we omit them, the program creates Default_Node.json as a file and Default_Folder as a directory**

# Project 3: Link State Routing

Due: **Dec 11, 2024**

## Overview

In this programming assignment, you will modify the emulators that you implemented in project 2, to perform a link-state routing protocol to determine the shortest paths between a fixed, known set of nodes in the lab. The paths between the nodes will be reconfigurable and new routes must stabilize within a fixed time period.

Your emulators will also forward packets from the routetrace application that you will build to the node which is the next hop in the shortest path to a specified destination.

In this assignment, we will not provide you with each and every detail of how you should implement the link-state protocol. Instead, we will specify a set of requirements that your program should satisfy.

As with the first two programming assignments, you are to work in teams and write your code in python and submit your codes into Canvas.

## Project Details

Each node in the network is defined by an {IP,port} pair. After start-up, each emulator will implement the following functions: readtopology, createroutes, forwardpacket, and buildForwardTable .

### readtopology

**readtopology** will read a text file (topology.txt) which defines the interconnection structure of a test network that can have up to 20 nodes. The topology structure will be stored in a file and will have the following format:

```
IP_a,port_w IP_b,port_x,distance_1 IP_c,port_y,distance_2 IP_d,port_z,distance_3 …
IP_b,port_x IP_a,port_w,distance_1 IP_c,port_y,distance_4 IP_d,port_z,distance_5 …
...
```

The first {IP,port} pair in each line of the topology file corresponds to a node which is running an emulator and will be listening for packets from all of the remaining {IP,port} pairs in the line (ie. a one-way connection to the first node from all of the other nodes). The pairs are separated by a whitespace character. You can assume that there will be bidirectional connections to and from each node in the topology and that the topology file will be set up to reflect this. The distance after {IP,port} pairs specifies the distance between two nodes. A simple network has topology as follows:

![Route Topology](route-topology.png "Visualized route topology")

Imagine we have a network with above topology, and here are the IP addresses and ports for each node:

| Node |    IP   | Port |
|------|---------|------|
|  1   | 1.0.0.0 |  1   |
|  2   | 2.0.0.0 |  2   |
|  3   | 3.0.0.0 |  3   |
|  4   | 4.0.0.0 |  4   |
|  5   | 5.0.0.0 |  5   |
 

The topology.txt will then look like:

```
1.0.0.0,1 2.0.0.0,2,6 3.0.0.0,3,10
2.0.0.0,2 1.0.0.0,1,6 3.0.0.0,3,8 5.0.0.0,5,7
3.0.0.0,3 1.0.0.0,1,10 2.0.0.0,2,8 4.0.0.0,4,6
4.0.0.0,4 3.0.0.0,3,6 5.0.0.0,5,11
5.0.0.0,5 2.0.0.0,2,7 4.0.0.0,4,11
```

After executing the readtopology, you can assume that all nodes in the topology.txt are “alive” and that the process of setting up the route topology and forwarding table should begin. readtopology only needs to be executed once when the emulator is started and the application can assume that the topology file (topology.txt) is in the same directory in which the emulator code is running. Note that this means that the emulator knows the whole topology at the startup. After that, the emulator will call buildForwardTable (described below)  to calculate the shortest path to other nodes based on this topology. Note that the topology might be updated later when some nodes come up or go down.

### createroutes

You should firstly refer to the course textbook for details (from page 252 to 258) on how the link-state protocol works.

**createroutes** will implement a link-state routing protocol to set up a shortest path forwarding table between nodes in the specified topology. Through this function, each emulator should maintain the following datas:

1. The **route topology** containing the interconnection structure of the whole network.
2. The **forwarding table** containing entries in the form of (Destination, Nexthop), where Nexthop is the next node on the shortest path from current emulator to the destination. Both Destination and Nexthop are {IP, port} pairs. It is calculated by calling the buildForwardTable function with the route topology as the input, which will be described later.
3. The **latest timestamp** of the received HelloMessage from each of its neighbors. It will be a list of pairs (Neighbor, Timestamp). It will be described with more details later.
4. The **largest sequence number** of the received LinkStateMessages from each node except itself. It will be a list of pairs (Node, Largest Seq No). It will also be described with more details later.

The routing topology and the forwarding table must be updated if a node state change takes place. The createroutes function should run continuously after the initial route topology and forwarding table have been specified by readtopology. It must be designed to react to nodes being responsive or unresponsive in the network and will require link-state information to be transmitted between an emulator and its neighbors.

The interval of transmission (ie. how frequently updates are sent) is up to you as is the mode of transport (TCP or UDP) and the link-state packet format. However you must ensure that your routing topology stabilizes within **5 seconds** after a node state change takes place (For example when emulator 3 is died). Note that weights on each link can be different.

### Notes

- Note that you should implement the link-state protocol. Thus, you should implement the "reliable flooding" algorithm where each node communicates only with its neighbors. It is true that your emulator can figure out every node on the topology from the topology file but it is NOT OK to contact any node other than your neighbors directly in this implementation.
- Note that your shortest path computations should be updated both when a node goes down, and when a node comes up.
- Here are the messages you need to send and handle in this function:
  1. **HelloMessage**: At defined intervals, each emulator should send the  HelloMessage to its immediate neighbors. The goal of this message is letting the node know the state of its immediate neighbors.  
     1. If a sufficiently long time passes without receipt of a “hello” from a neighbor, the link to that neighbor will be declared unavailable. In this case, you need to change the route topology and forwarding table stored in this emulator, and generate a new LinkStateMessage to reflect this fact. 
     2. Similarly, when handling the helloMessage coming from an unavailable neighbor, you should declare it available, update the route topology and forwarding table, and generate a new LinkStateMessage.
   2. **LinkStateMessage**: At defined intervals, each emulator should send a LinkStateMessage to its immediate neighbors. It contains the following information:
      1. The (ip, port) pair of the node that created the message.
      2. A list of directly connected neighbors of that node, with the cost of the link to each one.
      3. A sequence number. Incremental by one each time the information b is updated and a new LinkStateMessage is generated. 
      4. A time to live (TTL) for this packet. 
   3. In this lab, you can assume that your helloMessage and LinkStateMessage will not be lost.
   4. The packet format of these messages is up to you. Also, you can decide the initial TTL and sequence number of LinkStateMessage by yourselves.
- Your emulator can follow the steps below in an infinite loop and no threading is required for this assignment. You can also design your own link-state protocol based on the textbook.
   1. Receive packet from network in a non-blocking way. This means that you should not wait/get blocked in the recvfrom function until you get a packet. Check if you have received a packet; If not jump to 3,
   2. Once you receive a packet, decide the type of the packet. 
       - If it is a helloMessage, your code should
           1. Update the latest timestamp for receiving the helloMessage from the specific neighbor.
           2. Check the route topology stored in this emulator. If the sender of helloMessage is from a previously unavailable node, change the route topology and forwarding table stored in this emulator. Then generate and send a new LinkStateMessage to its neighbors.
       - If it is a LinkSateMessage, your code should 
           1. Check the largest sequence number of the sender node to determine whether it is an old message. If it’s an old message, ignore it. 
           2. If the topology changes, update the route topology and forwarding table stored in this emulator if needed.
           3. Call forwardpacket function to make a process of flooding the LinkStateMessage to its own neighbors.
       - If it is a DataPacket / EndPacket / RequestPacket in Lab 2, forward it to the nexthop. You don't need to do queueing, delaying and dropping.
       - If it is a routetrace packet (described below), refer to the routetrace application part for correct implementation.
   3. Send helloMessage to all neighbors if a defined interval has passed since last time sending the helloMessage.
   4. Check each neighbor, if helloMessage hasn’t received in time (comparing to the latest timestamp of the received HelloMessage from that neighbor), remove the neighbor from route topology, call the buildForwardTable to rebuild the forward table, and update the send new LinkStateMessage to its neighbors.
   5. Send the newest LinkStateMessage to all neighbors if the defined intervals have passed.

### forwardpacket

**forwardpacket** will determine whether to forward a packet and where to forward a packet received by an emulator in the network. Your emulator should be able to handle both packets regarding the LinkStateMessage, and packets that are forwarded to it from the routetrace application (described below). For LinkStateMessage, you need to forward the LinkStateMessage to all its neighbors except where it comes from. However, when TTL (time to live) decreases to 0, you don’t need to forward this packet anymore.

### buildForwardTable

**buildForwardTable** will use the forward search algorithm (see page 256-258 in the textbook) to compute a forwarding table based on the topology it collected from LinkStateMessage. The forwarding table contains entries in the form of (Destination, Nexthop). Anytime an emulator node detects a change of its topology, it should call the buildForwardTable function to update its forwarding table.

### Emulator

The emulator will be invoked as follows:

```
python3 emulator.py -p <port> -f <filename>
```

- **port**: the port that the emulator listens on for incoming packets.
- **filename**: the name of the topology file described above.

Note that for each emulator, you are required to print the topology and forwarding table each time it’s changed. See the example section for more details. You might want to print some other debugging information from the emulator so that if your program is not behaving as expected at the demo time we can analyze what your program does and does not do correctly. 

## routetrace Details

**routetrace** is an application similar to the standard traceroute tool which will trace the hops along a shortest path between the source and destination emulators. routetrace will send packets to the source emulator with successively larger time-to-live values until the destination node is reached and will produce an output showing the shortest path to the destination. You will use this application to verify that your implementation of link-state protocol has the correct shortest paths between the nodes.

This application will generate an output that traces the shortest path between the source and destination node in the network that is given to it by the command line parameters below. An instance of routetrace will be invoked as follows:

```
python3 trace.py -a <routetrace port> -b < source hostname> -c <source port> -d <destination hostname> -e <destination port> -f <debug option>
```

- **routetrace port**: the port that the routetrace listens on for incoming packets.
- **source hostname**, **source port**, **destination hostname**, **destination port**: routetrace will output the shortest path between the <source hostname, source port> to <destination hostname, destination port> .
- **Debug option**: When the debug option is 1, the application will print out the following information about the packets that it sends and receives: TTL of the packet and the src. and dst. IP and port numbers. It will not do so when this option is 0.

Same as before, the specific packet format of these messages is up to you.This is the suggested fields of the routetrace packet for the routetrace application. 

- Time to Live
- Source IP, source port
- Destination IP, destination port

More concretely here is what the routetrace application does:

1. It gets the (IP, port) of the source node and destination node from the command line.
2. It sets the TTL of the packet to 0: TTL=0
3. Send a routetrace packet to the source node with packet fields:
    1. Time to Live: TTL, 
    2. Source IP, source port: routetrace IP, routetrace Port (from command line)
    3. Destination IP, destination port: Destination IP, Destination Port (from command line)
4. Wait for a response.
5. Once it gets a response, print out the responders IP and port (that it gets from the response packet).
6. If the source IP and port fields of the routetrace packet that it received equals the destination IP and port from the command line then TERMINATES.
7. Otherwise, TTL = TTL + 1, goto 3.

Here is what your emulator should do once it receives a routetrace packet:

- If TTL is 0, create a new routetrace packet. Put its own IP and Port to the source IP and port fields of the routetraceReply packet. Other fields of the packet should be identical to the packet it received. Send that back to the routetrace application (using the source IP and port fields of the routetrace packet that it received).
- If TTL is not 0, decrement the TTL field in the packet. Search in its route table and send the altered packet to the next hop on the shortest path to the destination.

## Example

The Ctrl+ C command on the terminal will be used to temporarily disable an emulator in the topology. The idea is that the topology must be reconfigurable on the fly. When an emulator is disabled, it will cease forwarding packets and cease sending its routing messages to its neighbors. When the emulator is started again, it will begin participating in routing and forwarding again and the shortest path routes will get updated.

Sample test case 1 (all links have the same weight 1):

Firstly, we start 5 emulators using topology1.txt. In topology1.txtLinks to an external site., we define a network looks like:

![Route Topology](route-topology.png "Visualized route topology")

We’ll give a sample output for the emulator with port 1 here. Other emulators have similar outputs. After the readtopology, it will print out the initial routing topology and forwarding table it gets from topology1.txt:

**Topology:**

```
1.0.0.0,1 2.0.0.0,2,1 3.0.0.0,3,1
2.0.0.0,2 1.0.0.0,1,1 3.0.0.0,3,1 5.0.0.0,5,1
3.0.0.0,3 1.0.0.0,1,1 2.0.0.0,2,1 4.0.0.0,4,1
4.0.0.0,4 3.0.0.0,3,1 5.0.0.0,5,1
5.0.0.0,5 2.0.0.0,2,1 4.0.0.0,4,1
```

**Forwarding table:**

|  Dest IP  |  Next Hop |
|-----------|-----------|
| 2.0.0.0,2 | 2.0.0.0,2 |
| 3.0.0.0,3 | 3.0.0.0,3 |
| 4.0.0.0,4 | 3.0.0.0,3 |
| 5.0.0.0,5 | 2.0.0.0,2 |

Consider the above topology. If we run the routetrace application between nodes 1 and 4, here is the output that the routetrace application should get:

| Hop# |    IP   | Port |
|------|---------|------|
|  1   | 1.0.0.0 |  1   |
|  2   | 3.0.0.0 |  3   |
|  3   | 4.0.0.0 |  4   |

Now let's disable emulator 3 by using the command Ctrl + C. Your routes should reconfigure. Within at most 5 seconds, the emulator with port 1 will print out the new topology and forwarding table:

**Topology:**

```
1.0.0.0,1 2.0.0.0,2,1
2.0.0.0,2 1.0.0.0,1,1 5.0.0.0,5,1
4.0.0.0,4 5.0.0.0,5,1
5.0.0.0,5 2.0.0.0,2,1 4.0.0.0,4,1
```

**Forwarding table:**

|  Dest IP  |  Next Hop |
|-----------|-----------|
| 2.0.0.0,2 | 2.0.0.0,2 |
| 4.0.0.0,4 | 2.0.0.0,2 |
| 5.0.0.0,5 | 2.0.0.0,2 |

Once we run the routetrace application again after a few seconds, we should get:

| Hop# |    IP   | Port |
|------|---------|------|
|  1   | 1.0.0.0 |  1   |
|  2   | 2.0.0.0 |  2   |
|  3   | 5.0.0.0 |  5   |
|  4   | 4.0.0.0 |  4   |

Your program will be tested similarly with another topology at the demo time.

Sample test case 2 (links have different weights):

Firstly, we start 5 emulators using topology2.txt. In topology2.txtLinks to an external site., we define a network looks like above:

![Route Topology](route-topology.png "Visualized route topology")

We’ll give a sample output for the emulator with port 1 here. Other emulators have similar outputs. After the readtopology, it will print out the initial routing topology and forwarding table it gets from topology2.txt:

**Topology:**

```
1.0.0.0,1 2.0.0.0,2,2 3.0.0.0,3,2
2.0.0.0,2 1.0.0.0,1,2 3.0.0.0,3,3 5.0.0.0,5,9
3.0.0.0,3 1.0.0.0,1,2 2.0.0.0,2,3 4.0.0.0,4,3
4.0.0.0,4 3.0.0.0,3,3 5.0.0.0,5,4
5.0.0.0,5 2.0.0.0,2,9 4.0.0.0,4,4
```

**Forwarding table:**

|  Dest IP  |  Next Hop |
|-----------|-----------|
| 2.0.0.0,2 | 2.0.0.0,2 |
| 3.0.0.0,3 | 3.0.0.0,3 |
| 4.0.0.0,4 | 3.0.0.0,3 |
| 5.0.0.0,5 | 3.0.0.0,3 |

Consider the above topology. If we run the routetrace application between nodes 1 and 4, here is the output that the routetrace application should get:

| Hop# |    IP   | Port |
|------|---------|------|
|  1   | 1.0.0.0 |  1   |
|  2   | 3.0.0.0 |  3   |
|  3   | 4.0.0.0 |  4   |

Now let's disable emulator 3 by using the command Ctrl + C. Your routes should reconfigure. Within at most 5 seconds, the emulator with port 1 will print out the new topology and forwarding table:

**Topology:**

```
1.0.0.0,1 2.0.0.0,2,2
2.0.0.0,2 1.0.0.0,1,2 5.0.0.0,5,9
4.0.0.0,4 5.0.0.0,5,4
5.0.0.0,5 2.0.0.0,2,9 4.0.0.0,4,4
```

**Forwarding table:**

|  Dest IP  |  Next Hop |
|-----------|-----------|
| 2.0.0.0,2 | 2.0.0.0,2 |
| 4.0.0.0,4 | 2.0.0.0,2 |
| 5.0.0.0,5 | 2.0.0.0,2 |

Once we run the routetrace application again after a few seconds, we should get:

| Hop# |    IP   | Port |
|------|---------|------|
|  1   | 1.0.0.0 |  1   |
|  2   | 2.0.0.0 |  2   |
|  3   | 5.0.0.0 |  5   |
|  4   | 4.0.0.0 |  4   |

 

## Submission

The executable program names must be "emulator.py" and "trace.py". You may also submit a “readme.txt” file if you need it. If you choose to work with a partner, please have only one partner submit your code and include a file named “partner.txt” in the submission that lists the names and email addresses of both partners. 

To turn in your code, please put your .py files and .txt files to a directory named “Lab3”, then zip the directory to a .zip file.

Important note: You are responsible to make sure that your code works on the CSL machines before you hand the code in (ssh to these machines and test your code even if you are working in another computer).

## Grading

When grading, we’ll use a topology different from the one in the example. Note that you should print your route topology and forwarding table in a nice way once it changes. Here are the requirements you should follow and their weights:

- 10 : You have implemented the readtopology function and each emulator knows its neighbors.
- 15 : You have implemented the createroutes function and it can detect the state change of its neighbor by sending and handling helloMessage successfully.
- 15 : You have implemented the createroutes function and it can detect the state change of any nodes by sending and handling LinkStatePacket successfully.
- 10 : You have implemented the forwardpacket function to forward packets from the routetrace application and other emulators.
- 10 : You have implemented the buildForwardTable function with the forward search algorithm to calculate the shortest path to each destination.
- 20 : You have correctly implemented the routetrace application.
- 20 : Shortest path routes that routetrace prints are correct and reconfigure when emulators are disabled or enabled after they are disabled. 
- 5 (extra credits) : Forward packets between sender and receiver using the capabilities developed in project 2 following the shortest path route through your emulated network. 

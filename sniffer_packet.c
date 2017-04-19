#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
#include<gtk/gtk.h> 
void extractHeader(unsigned char* , int);
void IP_header(unsigned char* , int);
void TCP_header(unsigned char * , int );
void UDP_header(unsigned char * , int );
void PrintData (unsigned char* , int);
void print_http_header(unsigned char* , int);
void print_ftp_header(unsigned char* , int);
FILE *file;
struct sockaddr_in source,dest;
int tcp=0,udp=0,total=0,i,j; 
 
void main2()
{
    int saddr_size;
    struct sockaddr saddr;
         
    unsigned char *buffer = (unsigned char *) malloc(65536);
	memset(buffer,'\0',65536);
    file=fopen("result.txt","w+");
	if(file==NULL) { //checking if the file is not opened correctly
		printf("error opening result.txt file.");
	}  
  
	printf("Sniffing...\n");
     
        int mysocket;
	mysocket = socket (AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
	if(mysocket < 0)
	{ //checks if socket initiated correctly
		printf("Socket not connected");
		//return 1; 
	}
    while(1)
    {
        saddr_size = sizeof saddr;
        //Receive a packet
        int pkt_size;
	pkt_size=recvfrom(mysocket , buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
	if(pkt_size <0 )
	{
		printf("error in getting packets\n");
		//return 1;
	}        //Now process the packet
        extractHeader(buffer , pkt_size);
    }
    close(mysocket);
    printf("Finished");
    
}
void extractHeader(unsigned char* buffer, int pkt_size)
{
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *ip_head = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    	
	if(ip_head->protocol==6){
		++tcp;
		TCP_header(buffer, pkt_size);
	}
	else if(ip_head->protocol==17){
		++udp;
		UDP_header(buffer, pkt_size);
	}
	else{
		;
	}
    printf("TCP : %d   UDP : %d\r",tcp,udp);
}

void Ethernet_header(unsigned char* buffer, int pkt_size)
{
    struct ethhdr *et_head = (struct ethhdr *)buffer;
     
    fprintf(file , "\n");
    fprintf(file , "Ethernet Header\n");
    fprintf(file , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", et_head->h_dest[0] , et_head->h_dest[1] , et_head->h_dest[2] , et_head->h_dest[3] , et_head->h_dest[4] , et_head->h_dest[5] );
    fprintf(file , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", et_head->h_source[0] , et_head->h_source[1] , et_head->h_source[2] , et_head->h_source[3] , et_head->h_source[4] , et_head->h_source[5] );
    fprintf(file , "   |-Protocol            : %u \n",(unsigned short)et_head->h_proto);
}

void IP_header(unsigned char* buffer, int pkt_size)
{
    Ethernet_header(buffer , pkt_size);
   
    unsigned short iphdr_length;
         
    struct iphdr *ip_head = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
    iphdr_length =ip_head->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip_head->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip_head->daddr;
     
    fprintf(file , "\n");
    fprintf(file, "IP Header\n");
    fprintf(file , "   |-Protocol : %d\n",(unsigned int)ip_head->protocol);
    fprintf(file , "   |-IP Total Length   : %d  Bytes\n",ntohs(ip_head->tot_len));
    fprintf(file , "   |-IP Version        : %d\n",(unsigned int)ip_head->version);
    fprintf(file , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip_head->ihl,((unsigned int)(ip_head->ihl))*4);
    fprintf(file , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(file , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
    fprintf(file , "   |-Identification    : %d\n",ntohs(ip_head->id));
    fprintf(file , "   |-Type Of Service   : %d\n",(unsigned int)ip_head->tos);
    fprintf(file , "   |-TTL      : %d\n",(unsigned int)ip_head->ttl);
    fprintf(file , "   |-Checksum : %d\n",ntohs(ip_head->check));
}

void TCP_header(unsigned char* buffer, int pkt_size)
{
    unsigned short iphdr_length;
     
    struct iphdr *ip_head = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
    iphdr_length = ip_head->ihl*4;
     
    struct tcphdr *tcp_head=(struct tcphdr*)(buffer + iphdr_length + sizeof(struct ethhdr));
   
    if(ntohs(tcp_head->dest)==443 || ntohs(tcp_head->dest)==80){
	print_http_header(buffer,pkt_size);
    }
    if(ntohs(tcp_head->dest)==21){
	print_ftp_header(buffer,pkt_size);
    }       
    int hdr_len =  sizeof(struct ethhdr) + iphdr_length + tcp_head->doff*4;
     
    fprintf(file , "\n\nTCP Packet\n");  
         
    IP_header(buffer,pkt_size);
         
    fprintf(file , "\n");
    fprintf(file , "TCP Header\n");
    fprintf(file , "   |-Source Port      : %u\n",ntohs(tcp_head->source));
    fprintf(file , "   |-Destination Port : %u\n",ntohs(tcp_head->dest));
    fprintf(file , "   |-Sequence Number    : %u\n",ntohl(tcp_head->seq));
    fprintf(file , "   |-Acknowledge Number : %u\n",ntohl(tcp_head->ack_seq));
    fprintf(file , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp_head->doff,(unsigned int)tcp_head->doff*4);
    fprintf(file , "   |-Urgent Flag          : %d\n",(unsigned int)tcp_head->urg);
    fprintf(file , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcp_head->ack);
    fprintf(file , "   |-Push Flag            : %d\n",(unsigned int)tcp_head->psh);
    fprintf(file , "   |-Reset Flag           : %d\n",(unsigned int)tcp_head->rst);
    fprintf(file , "   |-Synchronise Flag     : %d\n",(unsigned int)tcp_head->syn);
    fprintf(file , "   |-Finish Flag          : %d\n",(unsigned int)tcp_head->fin);
    fprintf(file , "   |-Receive Window         : %d\n",ntohs(tcp_head->window));
    fprintf(file , "   |-Checksum       : %d\n",ntohs(tcp_head->check));
    fprintf(file , "   |-Urgent Pointer : %d\n",tcp_head->urg_ptr);
    fprintf(file , "DATA Dump\n");
         
    fprintf(file , "IP Header\n");
 PrintData(buffer,iphdr_length);
         
    fprintf(file , "TCP Header\n");
  PrintData(buffer+iphdr_length,tcp_head->doff*4);
         
    fprintf(file , "Data Payload\n");    
    PrintData(buffer + hdr_len , pkt_size - hdr_len );
                         
}

void UDP_header(unsigned char* buffer, int pkt_size)
{
    unsigned short iphdr_length;
     
    struct iphdr *ip_head = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
    iphdr_length = ip_head->ihl*4;
     
    struct udphdr *udp_head=(struct udphdr*)(buffer + iphdr_length + sizeof(struct ethhdr));
   
    int hdr_len =  sizeof(struct ethhdr) + iphdr_length + sizeof udp_head;
     
    fprintf(file , "\n\nUDP Packet\n");  
         
    IP_header(buffer,pkt_size);
         
    fprintf(file , "\n");
    fprintf(file , "UDP Header\n");
    fprintf(file , "   |-Source Port      : %u\n",ntohs(udp_head->source));
    fprintf(file , "   |-Destination Port : %u\n",ntohs(udp_head->dest));
    fprintf(file , "   |-UDP Length      : %d\n" ,ntohs(udp_head->len));
    fprintf(file , "   |-Checksum       : %d\n",ntohs(udp_head->check));         
    fprintf(file , "IP Header\n");
     PrintData(buffer , iphdr_length);
         
    fprintf(file , "UDP Header\n");
   PrintData(buffer+iphdr_length , sizeof udp_head);
         
    fprintf(file , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(buffer  + hdr_len , pkt_size - hdr_len);
                        
}

void  print_http_header(unsigned char* Buffer , int Size){
	fprintf(file,"HTTP Header\n");

	PrintData (Buffer , Size);
}

void print_ftp_header(unsigned char* Buffer , int Size){
	fprintf(file,"FTP\n");
	PrintData (Buffer , Size);
}

void PrintData (unsigned char* data , int Size){	
	int i,j;
	
	for(i=0;i<Size;i++){
           
	if(data[i]>=32 && data[i]<=128) 
                {
                  fprintf(file,"%c",(unsigned char)data[i]);
                }
                else
                {
                  fprintf(file," ");
                }

}
fprintf(file, "\n");
}

gint delete_event_handler(GtkWidget* widget, GdkEvent* event, gpointer data){  
       g_print("delete event occured\n");  
       return FALSE;  
  }  
  void destroy(GtkWidget* widget, gpointer data){  
       gtk_main_quit();  
  }  


int main(int argc, char *argv[]){  
       GtkWidget *window;  
       GtkWidget *button_start;  
       gtk_init(&argc, &argv);  
       window = gtk_window_new(GTK_WINDOW_TOPLEVEL);  
       g_signal_connect(G_OBJECT(window), "delete_event", G_CALLBACK(delete_event_handler), NULL);  
       g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(destroy), NULL);  
       gtk_container_set_border_width(GTK_CONTAINER(window), 10);  
       button_start = gtk_button_new_with_label("START");  
       g_signal_connect(G_OBJECT(button_start), "clicked", G_CALLBACK(main2), NULL);  
       gtk_container_add(GTK_CONTAINER(window), button_start);  
       gtk_widget_show(button_start);  
       gtk_widget_show(window);  
       gtk_main();  
       return 0;  
  }  


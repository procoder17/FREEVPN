#include "FreeVpnClient.h"

#ifdef __cplusplus
extern "C"
{
#endif
// C header here
	#define bool LIBRARY_bool
	#include "n2n.h"
	#undef bool
	
	
	#ifdef WIN32
	#include <sys/stat.h>
	#endif

#ifdef __cplusplus
}
#endif

#define IMAGECLASS FreeVpnClientTray
#define IMAGEFILE  <FreeVpn/FreeVpnClient.iml>
#include <Draw/iml_source.h>

void notifyProgress(int percentage, void* view)
{
	FreeVpnClient* ui = (FreeVpnClient*)view;
	
	PostCallback([=](){
		if(percentage < 0)
			ui->btn.end = 0; //restart animation
		ui->btn.limit = abs(percentage);
		if(percentage == 100){
			ui->status = VPN_CONNECTED;
			ui->txt_status.SetText("Connected.");
		}else
			ui->txt_status.SetText("Connecting...");
	});
}
void logEvents(char* message, void* view)
{
	FreeVpnClient* ui = (FreeVpnClient*)view;
	PostCallback([=](){
		ui->logview.Append(message);
		free(message);
	});
}

FreeVpnClient::FreeVpnClient()
{
	CtrlLayout(*this, "FreeVpnClient");
	CenterScreen();
	MinimizeBox(true);
	status = VPN_DISCONNECTED;
	
	ipsets="";
	domains="";
	ips="";
	//server_ip.SetText("192.168.100.201");
	server_ip.SetText("180.235.134.11");
	server_port.SetText("8888");
	
	Add(btn);
	btn.SetRect(btn_pos.GetRect());
	btn_pos.Hide();
	btn <<= THISBACK(OnClicked);
	btn_connect.Hide();
	btn_disconnect.Hide();
	logview.Hide();
#ifdef WIN32
	btn_quit.Hide();
#endif
	btn_quit <<= THISBACK(OnQuit);
	Icon(FreeVpnClientTray::MainIcon());
}

void FreeVpnClient::Paint(Draw &w){
	Rect r(GetSize());
	w.DrawRect(r, Color(63, 62, 57));
}

void FreeVpnClient::Connect()
{
	if(status != VPN_DISCONNECTED)
		return;
	if(server_ip.GetText().ToString().IsEmpty())
		return;
	if(server_port.GetText().ToString().IsEmpty())
		return;
	server_info = server_ip.GetText().ToString()+":"+server_port.GetText().ToString();
	btn.StartAnimation();

	Thread().Run([=]
	{
		vpn_conf conf;
		memset(&conf, 0, sizeof(vpn_conf));
		conf.token = token;
		conf.ipsets = ipsets;
		conf.ips = ips;
		conf.domains = domains;
		conf.server_info = server_info;
		conf.notify = notifyProgress;
		conf.log_func = logEvents;
		conf.v = this;
		
		status = VPN_CONNECTING;
		startVpn(&conf);
		edge_term(&client);
		PostCallback([=] { 
#ifdef WIN32			
			Sleep(50);
#endif
			logview.Append("Disconnected\n"); 
			status = VPN_DISCONNECTED;
			btn.end = 0; //restart animation
			btn.limit = 0;
			txt_status.SetText("Disconnected.");
			Refresh();
		});
		
	});
}

void FreeVpnClient::OnClicked()
{
	if(status == VPN_CONNECTED || status == VPN_CONNECTING){
		Disconnect();
	}else if(status == VPN_DISCONNECTED){
		Connect();
	}
}
#ifdef PLATFORM_COCOA	
void FreeVpnClient::Close()
{
	Minimize(true);
}
#endif
void FreeVpnClient::Disconnect()
{
	if(status == VPN_DISCONNECTED || status == VPN_DISCONNECTING)
		return;
	txt_status.SetText("Disconnecting...");		//Disconnect
	btn.end = 0;
	btn.limit = 0;
	btn.StopAnimation();
	btn.Refresh();
	//logview.Append("Disconnecting.....\n"); 
	client.keep_on_running = 0;
}

void FreeVpnClient::OnQuit()
{
	if(status == VPN_DISCONNECTED){
		TopWindow::Close();
	}else{
		Disconnect();
	}
}
GUI_APP_MAIN
{

	Uniq uniq;
	if(!uniq)
		return;

	//MemoryBreakpoint(25654);
	//MemoryBreakpoint(22325);

	SignInWnd ui;

#ifdef WIN32
	ui.OpenMain();
	ui.Do();
#else
	
	ui.OpenMain();
	Ctrl::EventLoop();
#endif
}

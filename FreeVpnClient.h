#ifndef _FreeVpnClient_FreeVpnClient_h
#define _FreeVpnClient_FreeVpnClient_h


#include <CtrlLib/CtrlLib.h>

#ifdef PLATFORM_POSIX
#define UNIX
#endif

using namespace Upp;
#include <Uniq/Uniq.h>


#ifndef LAYOUTFILE
#define LAYOUTFILE <FreeVpn/FreeVpnClient.lay>
#endif
#include <CtrlCore/lay.h>

#include "CircularButton.h"

#define IMAGECLASS FreeVpnClientTray
#define IMAGEFILE  <FreeVpn/FreeVpnClient.iml>
#include <Draw/iml_header.h>

#define VPN_CONNECTING 1
#define VPN_DISCONNECTING 2
#define VPN_DISCONNECTED 3
#define VPN_CONNECTED 4


class FreeVpnClient;

class FreeVpnClient : public WithFreeVpnClientLayout<TopWindow>  {

	TopWindow::TopStyle style;
	Button::Style st;

public:
	typedef FreeVpnClient CLASSNAME;
	FreeVpnClient();
	Thread		 t;
	CircularButton btn;
	//bool isConnected;
	volatile Atomic  status;
	String token;
	String ipsets;
	String domains;
	String ips;
	String server_info;
	void Connect();
	void OnClicked();
	void Disconnect();
	void OnQuit();
#ifdef PLATFORM_COCOA
	virtual void Close();
#endif
    virtual void Paint(Draw & w) override;
};


class SignInWnd : public WithSignInLayout<TopWindow>  {
	Button::Style st;
	int didSigned;	
public:
	typedef SignInWnd CLASSNAME;
	SignInWnd();
#ifdef PLATFORM_WIN32	
	TrayIcon     trayicon;
#endif
	FreeVpnClient	 mainwnd;
	void OnContinueClicked();
	int Verify();
	int PullFilterLists();
	virtual void Paint(Draw & w) override;

    void TrayMenu(Bar& bar);
    void LeftDouble();
    void ExitApp();
    void ShowApp();
    void Connect();
	void OnClicked();
	void Disconnect();
	void Do();
};

#endif

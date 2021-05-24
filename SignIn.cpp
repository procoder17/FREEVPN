#include "FreeVpnClient.h"
#include <stdio.h>
#include <string.h>
//#include <Core/SSL/SSL.h>

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

void ModifyEditFieldStyle(EditField::Style& s, int radius) {
	
	// Extracted (and modified) from  CtrlLib/Ch.cpp : ChSynthetic(...)
	bool macos = false;
	int borderWidth = DPI(1);
	Color ink = SColorText();
	auto Espots = [=](const Image& m) { return WithHotSpots(m, DPI(radius), DPI(1), CH_EDITFIELD_IMAGE, DPI(radius)); };
	for(int i = 0; i < 4; i++) {
		s.activeedge = true;
//		Image MakeButton(int radius, Color face, double border_width, Color border_color, dword corner)
		s.edge[i] = Espots(MakeButton(radius,
		                              i == CTRL_DISABLED ? SColorFace() : SColorPaper(),
		                              macos && i == CTRL_PRESSED ? DPI(2) : borderWidth,
		                              i == CTRL_PRESSED ? SColorHighlight() : ink));
		if(i == 0)
			s.coloredge = Espots(MakeButton(radius, Black(), DPI(2), Null));
	}
}

void N2NFlatDarkSkin()
{
	
	Color color(63, 62, 57);
	ChReset();
	static int adj[] = { 10, 80, -5, -10 };
	SColorPaper_Write(color);
	SColorHighlight_Write(Gray());
	SColorHighlightText_Write(White());
	ChMakeSkin(3, SWhiteGray(), SWhiteGray(), adj);
	
}

Color BColor(){ return Color(59, 59, 59);};
const ColorF *N2NBorder()
{
	static ColorF data[] = {
		(ColorF)1,
		&BColor, &BColor, &BColor, &BColor,
	};
	return data;
}


SignInWnd::SignInWnd()
{
	CtrlLayout(*this);
	MinimizeBox(true);
	btn_continue <<= THISBACK(OnContinueClicked);

	//Button::Style st = Button::NormalStyle();
	st = Button::StyleOk();
	/*
	st.look[0] = ChBorder(N2NBorder(), Color(64, 139, 255));
	st.look[1] = ChBorder(N2NBorder(), Color(59, 59, 59));
	*/
	//st.look[0] = MakeButton(3, Color(64, 139, 255), DPI(0), Color(59, 59, 59));
	st.look[0] = MakeButton(10, CreateImage(Size(DPI(10), DPI(10)), Color(64, 139, 255)), 2, Color(64, 139, 255), 15);
	st.look[1] = MakeButton(10, CreateImage(Size(DPI(10), DPI(10)), Gray()), 2, Gray(), 15);
	st.look[2] = MakeButton(10, CreateImage(Size(DPI(10), DPI(10)), Color(59, 59, 59)), 2,Color(59, 59, 59) , 15);
	st.textcolor[0] = White();
	st.textcolor[1] = White();
	/*
	Color color(0x2d, 0x34, 0x36);
	st.look[0] = Color(0x1d, 0x1d, 0x1d);
	//st.look[1] = Color(64, 139, 255);
	//st.look[2] = Gray();
	//st.look[3] = Gray();

	st.focus_use_ok = true;*/
	
	btn_continue.SetStyle(st);
#ifdef PLATFORM_WIN32	
	trayicon.WhenBar = THISBACK(TrayMenu);
	trayicon.WhenLeftDouble = THISBACK(LeftDouble);
	trayicon.Icon(FreeVpnClientTray::MainIcon());
#endif

	SetSkin(N2NFlatDarkSkin);
	ModifyEditFieldStyle( EditField::StyleDefault().Write(), 12 );
	Transparent(true);
	Icon(FreeVpnClientTray::MainIcon());
}
void SignInWnd::Paint(Draw &w){
	
	Rect r(GetSize());
	w.DrawRect(r, Color(63, 62, 57));
}
int SignInWnd::PullFilterLists()
{
	HttpRequest req;
	req.RequestTimeout(3000).MaxRetries(0);
	req.Url("https://dev.deliciousbrains.com:8000/filterlist").Timeout(0);
	HttpRequest::Trace();
	req.ContentType("application/json");
	String postData = "{\"token\":\"" + mainwnd.token + "\"}";
	req.PostData(postData);
	req.POST();

	String token = req.Execute();
	if(req.IsSuccess()){
		token =  req.GetContent();
		Value res = ParseJSON(token);
		String is_success = res["res"];
		if(is_success == "ok"){
			mainwnd.ipsets = res["ipsets"];
			mainwnd.domains = res["domains"];
			mainwnd.ips = res["ips"];
			return 1;
		}else{
			return -1;
		}


	}else{
		return -1;
	}		            
	
}
void SignInWnd::OnContinueClicked()
{
	btn_continue.SetLabel("Connecting...");
	int ret = 0;
	PostCallback([=, &ret](){
		ret = Verify();
		btn_continue.SetLabel("Sign In");
		if(ret == -1){
			PromptOK("Failed to connect to authentication server!");
			return;
		}else if(ret == 0){
			PromptOK("Failed to sign in!");
			return;
		}else{
			PullFilterLists();
			Hide();
#ifdef PLATFORM_COCOA		
			Close();
#endif
			mainwnd.OpenMain();
		}
	});
	
	/*
	if(!Verify()){
		PromptOK("Sign In Failed!");
		return;
	};
	TopWindow::Hide();
	mainwnd.OpenMain();*/

}

int SignInWnd::Verify()
{
	
	HttpRequest req;
	req.RequestTimeout(3000).MaxRetries(0);
	req.Url("https://dev.deliciousbrains.com:8000/").Timeout(0);
	HttpRequest::Trace();
	req.ContentType("application/json");
	req.PostData("{\"email\":\"test@test.com\", \"password\":\"test\"}");
	req.POST();

	//String token = "";
	String token = req.Execute();
	/*
	bool keeping = true;
	while(keeping){
		ProcessEvents();
		SocketWaitEvent we;
		we.Add(req, req.GetWaitEvents());
		we.Wait(10);
		keeping = req.Do();
	}
	*/
	if(req.IsSuccess()){
		token =  req.GetContent();
		Value res = ParseJSON(token);
		mainwnd.token = res["res"];
		didSigned = mainwnd.token != "error"? (mainwnd.token != "" ? 1 : 0): 0;
	}else{
		didSigned = -1;
	}		            
	
	//mainwnd.token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InByb2NvZGVyMTdAb3V0bG9vay5jb20iLCJpYXQiOjE2MTg3MTE1MzksImV4cCI6MTYxODc0NzUzOX0.rnyl10bnGfTj-spB3nMV3_fCW3NKHmvv3kQ_l7QcakEK8Q0hAlAB05x4gxGR_6obvkd4Zm0NEge5qx9M8blfsQ";
	return didSigned;
}
void SignInWnd::TrayMenu(Bar& bar) {
	
	if(!didSigned){
		bar.Add("Show Window", THISBACK(ShowApp));
		bar.Add("Exit...", THISBACK(ExitApp));
	}else{
	    bar.Add("Connect...", THISBACK(Connect));
	    bar.Add("Disconnect...", THISBACK(Disconnect));
	   	bar.Separator();
	   	bar.Add("Show Window", THISBACK(ShowApp));
	    bar.Add("Exit...", THISBACK(ExitApp));
	}

}
void SignInWnd::Connect()
{
	mainwnd.Connect();
}
void SignInWnd::OnClicked()
{
	mainwnd.OnClicked();
}
void SignInWnd::Disconnect()
{
	mainwnd.Disconnect();
}
void SignInWnd::LeftDouble()
{
	ShowApp();
}
/*
void SignInWnd::LeftDown()
{
	ShowApp();
}*/
void SignInWnd::ShowApp()
{
	if(!didSigned){
		Execute();
	}else{
		if(!mainwnd.IsOpen())
			mainwnd.OpenMain();
	}
}
void SignInWnd::Do()
{
#ifdef WIN32
	trayicon.Run();
#endif
}
void SignInWnd::ExitApp()
{
	if(mainwnd.status == VPN_DISCONNECTED){
		Break();
#ifdef PLATFORM_WIN32
		trayicon.Break();
#endif
	}else{
		Disconnect();
	}

}
#ifndef _FreeVpnClient_CircularButton_h_
#define _FreeVpnClient_CircularButton_h_

#include <CtrlLib/CtrlLib.h>

using namespace Upp;

#define IMAGECLASS FreeVpnClientImgs
#define IMAGEFILE  <FreeVpn/FreeVpnClient.iml>
#include <Draw/iml_header.h>


class CircularButton : public Button {
	bool is_on;
	Image   img;
	ImageBuffer img_buf;
	Color	look[4];
	Color	animation;
	int timerId;
public:
	int start;
	int end;
	int limit;
	CircularButton();
//	virtual void   LeftDown(Point, dword);
	virtual void   MouseEnter(Point, dword);
	virtual void   MouseLeave();
	virtual void Paint(Draw& w);
	void Animate();
//	void RestartAnimate();
	void SetFaceColor(Color color);
	void StartAnimation();
	void StopAnimation();
	typedef CircularButton CLASSNAME;
public:
	void SetOn(bool flag) { is_on = flag;}
};

#endif

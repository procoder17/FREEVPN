#include "CircularButton.h"

#define IMAGECLASS FreeVpnClientImgs
#define IMAGEFILE  <FreeVpn/FreeVpnClient.iml>
#include <Draw/iml_source.h>

#define STEPSIZE 100
Image CreateBall(int r, Color color)
{
	int rr = 2 * r;
	int r2 = r * r;
	ImageBuffer b(rr, rr);
	for(int y = 0; y < rr; y++)
		for(int x = 0; x < rr; x++) {
			RGBA& a = b[y][x];
			a.r = color.GetR();
			a.g = color.GetG();
			a.b = color.GetB();
			int q = ((x - r) * (x - r) + (y - r) * (y - r)) * 256 / r2;
			a.a = q <= 255 ? 255 : 0;
		}
	return b;
}
// start = 0, end = 10000
Image CreateArc(int r, int width, int start, int end, Color color)
{

	int rr = 2 * r;
	int r2 = r * r;
	ImageBuffer b(rr, rr);
	if(end > 100)
		end = 100;
	for(int y = 0; y < rr; y++)
		for(int x = 0; x < rr; x++) {
			b[y][x].r = 0;
			b[y][x].g = 0;
			b[y][x].b = 0;
			b[y][x].a = 0;
			/*
			RGBA& a = b[y][x];
			a.r = color.GetR();
			a.g = color.GetG();
			a.b = color.GetB();
			int q = ((x - r) * (x - r) + (y - r) * (y - r)) * 256 / r2;
			a.a = (q >= (255 - width) && q <= 256)  ? 255 : 0;
			*/
		}
	if(end == 0)
		return b;
	float PI = 3.141592654;
	float _start, _end;
	_start = (float)start / (float)STEPSIZE;
	_start = _start * 2.0 * PI  + PI / 2.0;
	
	_end = (float)end / (float)STEPSIZE;
	_end = _end * 2.0 * PI  + PI / 2.0;

	int x, y;
	for(float alpha = _start ;alpha <= _end; alpha += 0.003){
		for(int w = 0; w< width; w++){
			int tmpr = r - w;
			x = tmpr*cos(alpha) + r;
			y = -tmpr*sin(alpha) + r;
			RGBA& a = b[y][x];
			a.r = color.GetR();
			a.g = color.GetG();
			a.b = color.GetB();
			a.a = 255;
		}
	}
	return b;
}
CircularButton::CircularButton()
{
	img = FreeVpnClientImgs::ConnectButton();
	is_on = false;
	//Transparent(true);
	start = 0;
	end = 0;
	limit = 0;
	//look[0] = Color(0, 178, 255);
	//look[1] = Color(0, 178, 255);
	look[0] = Gray();
	look[1] = Color(44, 44, 40);
	animation = Color(0, 178, 255);
//SetRect(0, 0, img.GetWidth(), img.GetHeight());
}
void CircularButton::Paint(Draw& w)
{
	Rect r(GetSize());
	int width = r.GetWidth();
	int height = r.GetHeight();
	Image edge;
	if(HasMouse()){
		w.DrawEllipse(r.left, r.top, width, height, look[0]);
		edge = CreateArc(width/2 + 80, 5, 0, 100, look[0]);
	}else{
		edge = CreateArc(width/2 + 80, 5, 0, 100, look[1]);
	}
	//Image ball = CreateBall(width/2 + 40, face);
	edge = RescaleFilter(edge, width, height, FILTER_BSPLINE);
	w.DrawImage(r.left, r.top, edge);
	//animation
	Image anim = CreateArc(width/2 + 80, 20, start, end, animation);
	anim = RescaleFilter(anim, width, height, FILTER_BSPLINE);
	w.DrawImage(r.left, r.top, anim);
	
	w.DrawImage(r.left + width*0.2 ,r.top + height*0.2 ,RescaleFilter(img, width * 0.6, height * 0.6, FILTER_BSPLINE));
}
/*
void CircularButton::LeftDown(Point pt, dword dw)
{

}*/
void CircularButton::Animate()
{
	if(end > limit - 4){
		return;
	}
	if(end > 70){
		end = end + 15;
	}else{
		end = end + 10;
	}

	Refresh();
}
void CircularButton::StartAnimation()
{
	timerId = 100;
	SetTimeCallback(-100, THISBACK(Animate), timerId);
}
void CircularButton::StopAnimation()
{
	KillTimeCallback(timerId);
}
void  CircularButton::MouseEnter(Point, dword)
{
	Refresh();
}

void  CircularButton::MouseLeave()
{
	Refresh();
	Pusher::MouseLeave();
}

void CircularButton::SetFaceColor(Color color)
{
	look[0] = color;
}


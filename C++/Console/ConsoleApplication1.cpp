#include "include/verify.h"
// 设置控制台文本颜色
void SetConsoleTextColor(WORD color) {
	// 获取标准输出句柄
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	// 设置文本颜色
	SetConsoleTextAttribute(hConsole, color);
}
int main()
{
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleTextColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	
	int caozuoma;
	std::string card;
	std::cout << "1.login 2.Unbind";
	std::cin >> caozuoma;
	verify CVerify;
	switch (caozuoma)
	{
	case 1:
		std::cout << "please input your card:\n" << std::endl;
		std::cin >> card;
		CVerify.Login(card);
		getchar();
		if (!CVerify.GetVerify())
		{
			getchar();
			exit(0);
		}
		break;
	case 2:
		std::cout << "please input your card:\n" << std::endl;
		std::cin >> card;
		CVerify.Stripping_Equipment(card);
		getchar();
		break;
	default:
		std::cout << " numerror" << std::endl;
		getchar();
		break;
	}
	getchar();
	return 1;
}
// main.cpp

#include "pch.h"
#include "ServiceMain.h"

int main(int argc, char* argv[]) {
    // 获取服务实例
    ServiceMain* service = ServiceMain::GetInstance();
    
    // 运行服务
    service->Run(argc, argv);
    
    return 0;
}
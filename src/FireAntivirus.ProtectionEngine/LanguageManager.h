#pragma once

#include <string>
#include <unordered_map>
#include <mutex>

class LanguageManager {
private:
    static LanguageManager* instance;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> languageResources;
    std::string currentLanguage;
    std::mutex mutex;

    LanguageManager();
    ~LanguageManager();

    void LoadBuiltInResources();

public:
    static LanguageManager* GetInstance();

    std::string GetString(const std::string& key);
    std::string GetCurrentLanguage() const;
    void SetCurrentLanguage(const std::string& language);
    void LoadLanguageFromConfig();
    void SaveLanguageToConfig();
};

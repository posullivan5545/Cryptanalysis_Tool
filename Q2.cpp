/* Author: Paul O'Sullivan
// Date: 2/8/2024
// Program: Program to cryptanalyze Vigenere ciphertext when the key is unknown.
// Program assumes all capitlizied and alphabetical values entered, no special characters

ASCII VAlUES FOR CAPITALIZED ALPHABET 65:A to 90:Z
*/
#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <algorithm>
#include <unordered_map>

using namespace std;


const unordered_map<char, double> EN_REL_FREQ_VIG = {
    {'A', 0.0812}, {'B', 0.0149}, {'C', 0.0271}, {'D', 0.0432},
    {'E', 0.1202}, {'F', 0.0230}, {'G', 0.0203}, {'H', 0.0592},
    {'I', 0.0731}, {'J', 0.0010}, {'K', 0.0069}, {'L', 0.0398},
    {'M', 0.0261}, {'N', 0.0695}, {'O', 0.0768}, {'P', 0.0182},
    {'Q', 0.0011}, {'R', 0.0602}, {'S', 0.0628}, {'T', 0.0910},
    {'U', 0.0288}, {'V', 0.0111}, {'W', 0.0209}, {'X', 0.0017},
    {'Y', 0.0211}, {'Z', 0.0007}
};
// Code from Q1
string decryptVig(const string& cipher, const string& key) {
    string plain = "";
    for (int i = 0; i < cipher.length(); i++) {
        char c = cipher[i];
        char decrypt = ((c - 'A') - (key[i % key.length()] - 'A') + 26) % 26 + 'A';
        plain += decrypt;
    }
    return plain;
} // end decryptVig

double calculateIOC(const string& text) {
    unordered_map<char, int> letters;
    int total = 0;

    // Count the frequency of each letter
    for (int i = 0; i < text.length(); i++) {
        char c = text[i];
        letters[c]++;
        total++;
    } // end for

    double sum = 0.0;
    for (auto& entry : letters) {
        int val = entry.second;
        sum += val * (val - 1);
    }

    // Calculate the IOC
    double IOC = sum / (total * (total - 1));
    
    return IOC;
} // end calculateIOC

vector<int> kasiski(const string& text) {
    vector<int> distances;
    unordered_map<string, int> lastPos;
    for (int i = 0; i < text.length(); i++) {
        for (int length = 3; length <= 8; length++) { // Start from length 3
            if (i + length <= text.length()) {
                string substring = text.substr(i, length);
                auto it = lastPos.find(substring);
                if (it != lastPos.end()) {
                    distances.push_back(i - it->second);
                }
                lastPos[substring] = i;
            }
        } // inner
    } // outer
    return distances;
} // end kasiski

vector<string> subString(const string& text, int keyL) {
    vector<string> subs(keyL);
    for (int i = 0; i < text.length(); i++) {
        int index = i % keyL;
        subs[index] += text[i];
    }
    return subs;
} // end subString (Breaks text into keyL amount of substrings)

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
} // end gcd

int findProbableKeyLength(const vector<int>& distances) {
    vector<int> commonDen;
    for (int i = 0; i < distances.size(); i++) {
        for (int j = i + 1; j < distances.size(); j++) {
            commonDen.push_back(gcd(distances.at(i), distances.at(j)));
        }
    }
    int probable_key_length = 0;
    int max = 0;
    for (int i = 0; i < commonDen.size(); i++) {
        int count = 0;
        for (int j = 0; j < commonDen.size(); j++) {
            if (commonDen[j] == commonDen[i]) {
                count++;
            }
        }
        if (count > max) {
            max = count;
            probable_key_length = commonDen[i];
        }
    }
    return probable_key_length;
} // end findProbableKeyLength

unordered_map<char, double> getLetterFrequencies(const string& text) {
    unordered_map<char, int> count;
    for (int i = 0; i < text.length(); i++) {
        char c = text[i];
        count[c]++;
    }
    
    unordered_map<char, double> frequencies;
    for (const auto& pair : count) {
        frequencies[pair.first] = static_cast<double>(pair.second) / text.length();
    }
    return frequencies;
} // end getLetterFrequencies

string shift(const string& text, int amount) {
    string shifted = "";
    for (int i = 0 ; i < text.length(); i++) {
        char c = text[i];
        char shiftedChar = 'A' + ((c - 'A' - amount + 26) % 26);
        shifted += shiftedChar;
    }
    return shifted;
} // end shift

double corr(const string& text, const unordered_map<char, double>& letterF) {
    double sum = 0.0;
    for (int i = 0; i < text.length(); i++) {
        char c = text[i];
        sum += letterF.at(c) * EN_REL_FREQ_VIG.at(c);
    }
    return sum;
} // end corr (check frequency against english standard)

char findLetter(const string& text, const unordered_map<char, double>& letterF) {
    char keyLetter = ' ';
    double max = 0.0;
    for (int count = 0; count < 26; count++) {
        string shifted = shift(text, count);
        double correlation = corr(shifted, letterF);
        if (correlation > max) {
            max = correlation;
            keyLetter = 'A' + count;
        }
    }
    return keyLetter;
} // end findLetter

string getKey(const string& text, int keyLen) {
    string key = "";
    unordered_map<char, double> frequencies = getLetterFrequencies(text);
    for (int i = 0; i < keyLen; i++) {
        string c = "";
        for (int j = i; j < text.length(); j += keyLen) {
            c += text[j];
        }
        key += findLetter(c, frequencies);
    }
    return key;
} // end getKey

int main() {
    ifstream inputFile("cipherNoKey.txt");
    if (!inputFile) {
        cout << "Error with inputFile." << endl;
        return 1;
    }

    string line, cipher;
    while (getline(inputFile, line) && !line.empty()) {
        cipher += line;
    }

    vector<int> distances = kasiski(cipher);
    for (int i = 0; i < distances.size(); ++i) {
        cout << distances[i] << " ";
    }
    cout << endl;
    int probable_key_length = findProbableKeyLength(distances);
    cout << "Probable key length based on distances: " << probable_key_length << endl;

    vector<string> splitString = subString(cipher, probable_key_length);
    cout << "Calculated IOC:" << endl;
    for (int i = 0; i < splitString.size(); i++) {
        cout << calculateIOC(splitString.at(i)) << endl;
    }
    string possible_key = getKey(cipher, probable_key_length);
    cout << "The possible key: " << possible_key << endl;

    string plain = decryptVig(cipher, possible_key);

    ofstream outputFile("plainNoKey.txt");
    if (!outputFile) {
        cout << "Error with outputFile." << endl;
        return 1;
    }
    outputFile << plain;
    outputFile.close();
    cout << "Decrypted message sent to: plainNoKey.txt" << endl;


    return 0;
} // end main

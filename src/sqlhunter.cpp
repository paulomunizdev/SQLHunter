/*
 * Title:       SQL Hunter
 * Version:     0.0.1
 * Author:      Paulo Muniz
 * GitHub:      https://github.com/paulomunizdev/SQLHunter
 * Description: A scanning tool for identifying vulnerable websites using
 * predefined dorks.
 */

#include <curl/curl.h>
#include <sys/stat.h>  // For file permissions
#include <unistd.h>    // For the sleep function

#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

// Function for writing data received from curl
/*
 * @brief                  Function to write data received from curl into a
 * string buffer.
 * @param ptr              Pointer to the data received from curl.
 * @param size             Size of each data element.
 * @param nmemb            Number of data elements.
 * @param data             Pointer to a string buffer where the data will be
 * stored.
 * @return size_t          The total size of the data.
 */
size_t writeFunction(char *ptr, size_t size, size_t nmemb, std::string *data) {
  data->append(ptr, size * nmemb);
  return size * nmemb;
}

// Function to check if the server response contains SQL syntax error
/*
 * @brief                  Function to check if the server response contains SQL
 * syntax error.
 * @param response         The response received from the server.
 * @return bool            True if SQL syntax error is found, otherwise false.
 */
bool hasSQLError(const std::string &response) {
  // Common patterns for SQL syntax error
  std::string patterns[] = {"SQL syntax", "SQL Error", "MySQL Error",
                            "syntax error"};

  // Check if any of the patterns are present in the response
  for (const std::string &pattern : patterns) {
    if (response.find(pattern) != std::string::npos) {
      return true;
    }
  }

  return false;
}

// Function to check if the URL is susceptible to SQL injection
/*
 * @brief                  Function to check if the URL is susceptible to SQL
 * injection.
 * @param url              The URL to be checked.
 * @return bool            True if URL is vulnerable, otherwise false.
 */
bool isSQLInjectionVulnerable(const std::string &url) {
  std::cout << "Processing URL: " << url
            << std::endl;  // Print the processed URL
  // Basic CURL setup
  CURL *curl = curl_easy_init();
  if (!curl) {
    std::cerr << "Error initializing CURL." << std::endl;
    return false;
  }

  // URL to be tested
  std::string test_url = url + "'";
  // Buffer to store the server response
  std::string response_buffer;
  // CURL request configuration
  curl_easy_setopt(curl, CURLOPT_URL, test_url.c_str());
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // Follow redirects
  curl_easy_setopt(
      curl, CURLOPT_WRITEFUNCTION,
      writeFunction);  // Function for writing data received from curl
  // Set the output buffer
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);
  // Execute the CURL request
  CURLcode res = curl_easy_perform(curl);
  // Check for CURL request error
  if (res != CURLE_OK) {
    std::cerr << "Error executing CURL request: " << curl_easy_strerror(res)
              << std::endl;
    curl_easy_cleanup(curl);
    return false;
  }

  // Check if the response indicates an SQL syntax error
  bool is_vulnerable = hasSQLError(response_buffer);
  // Clean up CURL
  curl_easy_cleanup(curl);
  return is_vulnerable;
}

// Function to decode a URL
/*
 * @brief                  Function to decode a URL.
 * @param url              The URL to be decoded.
 * @return std::string     The decoded URL.
 */
std::string decodeUrl(const std::string &url) {
  std::string decoded;
  size_t length = url.length();
  for (size_t i = 0; i < length; ++i) {
    if (url[i] == '%' && i + 2 < length && isxdigit(url[i + 1]) &&
        isxdigit(url[i + 2])) {
      decoded +=
          static_cast<char>(std::stoi(url.substr(i + 1, 2), nullptr, 16));
      i += 2;
    } else {
      decoded += url[i];
    }
  }
  return decoded;
}

// Function to search and print links from HTML content
/*
 * @brief                  Function to search and print links from HTML content.
 * @param html             The HTML content where links will be searched.
 * @param outputFile       Output file stream where the links will be printed.
 */
void searchAndPrintLinks(const std::string &html, std::ofstream &outputFile) {
  std::regex linkRegex("<a href=\"([^\"]+)\"[^>]*>");
  std::sregex_iterator iter(html.begin(), html.end(), linkRegex);
  std::sregex_iterator end;
  while (iter != end) {
    std::smatch match = *iter;
    std::string link = match.str(1);
    if (link.find("/url?q=") == 0) {
      size_t startPos = link.find("=") + 1;
      size_t endPos = link.find("&");
      if (endPos != std::string::npos) {
        link = link.substr(startPos, endPos - startPos);
      }
      if (link.find("google.com") == std::string::npos) {
        CURLU *url = curl_url();
        if (url) {
          curl_url_set(url, CURLUPART_URL, link.c_str(), 0);
          char *urlDecoded;
          if (curl_url_get(url, CURLUPART_URL, &urlDecoded, 0) == CURLUE_OK) {
            std::string decodedUrl = decodeUrl(urlDecoded);
            std::cout << "URL: " << decodedUrl << std::endl;
            outputFile << decodedUrl << std::endl;
          }
          curl_free(urlDecoded);
          curl_url_cleanup(url);
        }
      }
    }
    ++iter;
  }
}

// Function to perform HTTP request
/*
 * @brief                  Function to perform HTTP request using CURL.
 * @param curl             Pointer to the CURL handle.
 * @param search_query     The URL or search query to be executed.
 * @param response_buffer  String buffer to store the response received from the
 * server.
 * @return CURLcode        CURL result code indicating the outcome of the
 * request.
 */
CURLcode performRequest(CURL *curl, const std::string &search_query,
                        std::string &response_buffer) {
  CURLcode res;
  response_buffer.clear();
  curl_easy_setopt(curl, CURLOPT_URL, search_query.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeFunction);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);
  res = curl_easy_perform(curl);
  return res;
}

int main() {
  // ASCII Art
  std::string art =
      "                           ______\n"
      "        |\\_______________ (_____\\\\______________\n"
      "HH======#H###############H#######################\n"
      "        ' ~\"\"\"\"\"\"\"\"\"\"\"\"\"\"`##(_))#H\"\"\"\"\"\"Y########\n"
      "                          ))    \\#H\\       `'Y###\n"
      "                          ''     }#H)";
  std::cout << art << std::endl;
  std::cout << "\nSQL Hunter - v0.0.1\n" << std::endl;
  std::cout << "" << std::endl;
  std::cout << "Before proceeding, please ensure you are using a proxy if "
               "necessary.\n"
            << std::endl;
  int choice;
  // Prompt user to choose an option
  std::cout << "Please choose an option:\n";
  std::cout << "[1] Dork Scanner\n";
  std::cout << "[2] Vuln Scanner\n";
  std::cout << "[3] Dork&Vuln Scanner\n";
  std::cin >> choice;
  switch (choice) {
    case 1: {
      // Dork Scanner option
      std::cout << "Please put the dorks in the 'dorks.txt' file. Press Enter "
                   "when ready."
                << std::endl;
      std::cin.ignore();  // Clear input buffer
      std::cin.get();     // Wait for user to press Enter
      std::cout << "Starting the Dork Scanner..." << std::endl;
      // Open "dorks.txt" file for reading
      std::ifstream dorksFile("dorks.txt");
      if (!dorksFile.is_open()) {
        std::cerr << "Error opening the 'dorks.txt' file." << std::endl;
        return 1;
      }

      // Open "links.txt" file for writing
      std::ofstream linksFile(
          "links.txt", std::ios_base::trunc);  // Overwrite previous content
      if (!linksFile.is_open()) {
        std::cerr << "Error opening the 'links.txt' file." << std::endl;
        return 1;
      }

      // Store dorks in a vector
      std::vector<std::string> dorks;
      std::string dork;
      while (std::getline(dorksFile, dork)) {
        dorks.push_back(dork);
      }
      dorksFile.close();
      int numPages;
      // Prompt user to enter the number of pages to scan
      std::cout << "Enter the number of pages to scan: ";
      std::cin >> numPages;
      std::string base_search_query;
      std::string search_query;
      std::string response_buffer;
      // Create the "links.txt" file with edit permissions
      chmod("links.txt",
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
      for (const auto &dork : dorks) {
        std::string modifiedDork = dork;
        base_search_query = "https://www.google.com/search?q=" + modifiedDork;
        for (int page = 0; page < numPages; ++page) {
          search_query =
              base_search_query + "&start=" + std::to_string(page * 10);
          CURL *curl;
          CURLcode res;
          curl = curl_easy_init();
          if (!curl) {
            std::cerr << "Error initializing cURL." << std::endl;
            return 1;
          }
          res = performRequest(curl, search_query, response_buffer);
          if (res != CURLE_OK) {
            std::cerr << "Failed to execute HTTP request." << std::endl;
            linksFile.close();
            curl_easy_cleanup(curl);
            return 1;
          }
          std::cout << "Links on page " << page + 1 << " for the dork \""
                    << dork << "\":" << std::endl;
          searchAndPrintLinks(response_buffer, linksFile);
          curl_easy_cleanup(curl);
        }
      }

      linksFile.close();
      std::cout << "Dork Scanner process completed." << std::endl;
      std::cout << "The links have been saved to the 'links.txt' file."
                << std::endl;
      break;
    }
    case 2: {
      // Vuln Scanner option
      std::cout << "Please put the links in the 'links.txt' file. Press Enter "
                   "when ready."
                << std::endl;
      std::cin.ignore();  // Clear input buffer
      std::cin.get();     // Wait for user to press Enter
      std::cout << "Starting the Vuln Scanner..." << std::endl;
      // Open "links.txt" file for reading
      std::ifstream linksFile("links.txt");
      if (!linksFile.is_open()) {
        std::cerr << "Error opening the 'links.txt' file." << std::endl;
        return 1;
      }

      // Open "vuln.txt" file for writing
      std::ofstream vulnFile(
          "vuln.txt", std::ios_base::trunc);  // Overwrite previous content
      if (!vulnFile.is_open()) {
        std::cerr << "Error opening the 'vuln.txt' file." << std::endl;
        return 1;
      }

      std::string url;
      // Read URLs from the file until the end
      while (std::getline(linksFile, url)) {
        // Check if the URL is vulnerable
        if (isSQLInjectionVulnerable(url)) {
          // If vulnerable, add to the "vuln.txt" file
          vulnFile << url << std::endl;
        }
      }

      // Close files
      linksFile.close();
      vulnFile.close();
      std::cout << "Vuln Scanner process completed." << std::endl;
      std::cout
          << "The vulnerable links have been saved to the 'vuln.txt' file."
          << std::endl;
      break;
    }
    case 3: {
      // Option 3: Dork Scanner followed by Vuln Scanner
      std::cout << "Option 3 selected: Dork Scanner followed by Vuln Scanner."
                << std::endl;
      // Open "dorks.txt" file for reading
      std::ifstream dorksFile("dorks.txt");
      if (!dorksFile.is_open()) {
        std::cerr << "Error opening the 'dorks.txt' file." << std::endl;
        return 1;
      }

      // Open "links.txt" file for writing
      std::ofstream linksFile("links.txt", std::ios::out | std::ios::trunc);
      if (!linksFile.is_open()) {
        std::cerr << "Error opening the 'links.txt' file." << std::endl;
        return 1;
      }

      // Change permissions of the "links.txt" file to allow editing
      chmod("links.txt",
            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
      std::vector<std::string> dorks;
      std::string dork;
      while (std::getline(dorksFile, dork)) {
        dorks.push_back(dork);
      }
      dorksFile.close();
      int numPages;
      // Prompt user to enter the number of pages to scan
      std::cout << "Enter the number of pages to scan: ";
      std::cin >> numPages;
      CURL *curl;
      CURLcode res;
      curl = curl_easy_init();
      if (!curl) {
        std::cerr << "Error initializing cURL." << std::endl;
        return 1;
      }

      std::string base_search_query;
      std::string search_query;
      std::string response_buffer;
      for (const auto &dork : dorks) {
        std::string modifiedDork = dork;
        std::replace(modifiedDork.begin(), modifiedDork.end(), ' ', '+');
        base_search_query = "https://www.google.com/search?q=" + modifiedDork;
        for (int page = 0; page < numPages; ++page) {
          search_query =
              base_search_query + "&start=" + std::to_string(page * 10);
          res = performRequest(curl, search_query, response_buffer);
          if (res != CURLE_OK) {
            std::cerr << "Failed to execute HTTP request." << std::endl;
            linksFile.close();
            curl_easy_cleanup(curl);
            return 1;
          }
          std::cout << "Links on page " << page + 1 << " for the dork \""
                    << dork << "\":" << std::endl;
          searchAndPrintLinks(response_buffer, linksFile);
        }
      }

      linksFile.close();
      curl_easy_cleanup(curl);
      std::cout << "Dork Scanner process completed. Links saved to the "
                   "'links.txt' file."
                << std::endl;
      // Execute Vuln Scanner
      std::cout << "Starting the Vuln Scanner after the Dork Scanner..."
                << std::endl;
      // Open "links.txt" file for reading
      std::ifstream file("links.txt");
      if (!file.is_open()) {
        std::cerr << "Error opening the 'links.txt' file." << std::endl;
        return 1;
      }

      // Open "vuln.txt" file for writing
      std::ofstream vulnFile("vuln.txt", std::ios_base::app);  // Append mode
      if (!vulnFile.is_open()) {
        std::cerr << "Error opening the 'vuln.txt' file." << std::endl;
        return 1;
      }

      // Read URLs from the file until the end
      std::string url;
      while (std::getline(file, url)) {
        // Check if the URL is vulnerable
        if (isSQLInjectionVulnerable(url)) {
          // If vulnerable, add to the "vuln.txt" file
          vulnFile << url << std::endl;
        }
      }

      // Close files
      file.close();
      vulnFile.close();
      std::cout << "Vuln Scanner process completed. Vulnerable URLs have been "
                   "added to the 'vuln.txt' file."
                << std::endl;
      break;
    }
    default:
      std::cerr << "Invalid option. Please choose a valid option." << std::endl;
      break;
  }

  return 0;
}

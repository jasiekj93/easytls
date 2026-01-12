/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <unistd.h>

#include <libeasytls/Server.hpp>

#include "SocketBio.hpp"
#include "CoutDebug.hpp"
#include "TimeImpl.hpp"

static const char certificatePem[] = 
"-----BEGIN CERTIFICATE-----\n"
"MIIEIzCCAwugAwIBAgIUTF9KnIw+/VULu9HvrGuniINc5mwwDQYJKoZIhvcNAQEL\n"
"BQAwejELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\n"
"DVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEVRlc3QgT3JnYW5pemF0aW9uMRAwDgYD\n"
"VQQLDAdUZXN0IENBMRAwDgYDVQQDDAdUZXN0IENBMB4XDTI1MTIxNTExNTUwMVoX\n"
"DTI2MTIxNTExNTUwMVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju\n"
"aWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEVRlc3QgT3JnYW5p\n"
"emF0aW9uMRIwEAYDVQQLDAlUZXN0IFVuaXQxEjAQBgNVBAMMCWxvY2FsaG9zdDCC\n"
"ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANbP31EP+x7qHlW9kVAPDkvn\n"
"fz69EtHuaaFwjOEz+gyzOeHMd4buoV9OqET6I8A5BYrKIwTUXjPuuU77c4u40id0\n"
"TOiGAiZjFYtbCC0MnsoaXmnzG9vYYMLfwGJILBfPGfOONemtDG6D50dZS8h/2HBJ\n"
"tlc4KsqfZ2j+7NAL09NQZGpQdCj8C4kRMBJ+8SCh7WKJeVwXtpofCTGag7hjibTg\n"
"MyQh131VloWMKh0KwfRHSTZvJ5XwwdDKQaL17i8i8VlQ5mXvVLxPMCBYq2U1TZ3g\n"
"Fkep230yzF9729Y2kcD/gjLQXuIdYgxSmor7VkzTnba80/HdKJRX/ZIlOaJ9kcsC\n"
"AwEAAaOBnDCBmTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAK\n"
"BggrBgEFBQcDATAnBgNVHREEIDAegglsb2NhbGhvc3SCC3Rlc3Qtc2VydmVyhwR/\n"
"AAABMB0GA1UdDgQWBBRlvRq4Zdh5v1PT4gWJtiZ5RlQIaDAfBgNVHSMEGDAWgBRa\n"
"Y5kjGxDYPxoJBBd6EKmS6mKFbzANBgkqhkiG9w0BAQsFAAOCAQEAWX8ioTrAUznw\n"
"AOBGAjMC1dwoAU1LvVJlLBlU5bP0Ij8lm/qHEcsue/l68Mln03UuuV5x2Ekdm4Iw\n"
"MT9xqdPnbOfGW7XLMGHlJNxEygersxx9HC/tTJ8Yl+e5dCQCV6wp19DzDSuEr3d/\n"
"ifp4J4envFTBanr8Ni+hcLAwTIWl9eYrVU/L0kx0IXeAzKoook9Z7mGYabHnDHQl\n"
"7AAbajDwdWKKL5MK7LFTgyiyHTEyjm8cQXhrsr8eK48xFjyFaIbl3lkf6zNgCzsj\n"
"0YIo7bpjm7vcoimxB2XswzPODw5mhGQWtnfz/59AAD+ZAA1lWd80GRyRFcCSIg0X\n"
"MB2JaCKZAA==\n"
"-----END CERTIFICATE-----\n";

static const char privateKeyPem[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWz99RD/se6h5V\n"
"vZFQDw5L538+vRLR7mmhcIzhM/oMsznhzHeG7qFfTqhE+iPAOQWKyiME1F4z7rlO\n"
"+3OLuNIndEzohgImYxWLWwgtDJ7KGl5p8xvb2GDC38BiSCwXzxnzjjXprQxug+dH\n"
"WUvIf9hwSbZXOCrKn2do/uzQC9PTUGRqUHQo/AuJETASfvEgoe1iiXlcF7aaHwkx\n"
"moO4Y4m04DMkIdd9VZaFjCodCsH0R0k2byeV8MHQykGi9e4vIvFZUOZl71S8TzAg\n"
"WKtlNU2d4BZHqdt9Msxfe9vWNpHA/4Iy0F7iHWIMUpqK+1ZM0522vNPx3SiUV/2S\n"
"JTmifZHLAgMBAAECggEAMwSJyEngXXZDIB/2vCnnPlXL3c2wA5X5FnORsgbTM2L5\n"
"s0wJc02HnAglZMR36zZfv5fEe2gou3LOJhkIVz3dA6vWfD8fkZhkzIUhSvm9WMis\n"
"dcNccXlRedcEbRMxDbKNOlAjM816r2C6dDKcEhFzCTAok0xutVLoj4JEIiE8/Omi\n"
"VgXafHJ4+Hm1u5YaAD3gNdjHhJe5YNdOsdhRftQwlEvALrEMw0KG+cLdufpMLgBO\n"
"6RjbCtPqoH04v17JlyfwY/1Z29BoCOEwdmWF046VJMJEVADG2vqhCIypOH9EXvAV\n"
"VRdJFMWL18D+X2LvyNLvCYjgKXgNhBWWjUJcR6xFoQKBgQD7ewgqigLhCEtGDGIN\n"
"L8Xu5/SrRqQVpoz4I2yJ3t+xYqqdMNTHDQO0DImKYdyCP4gCIkUhR20rqPAJzpF+\n"
"Wckx4eelTxFq80FWY9iDx1bXSfVzr2flnN/+GNTZD1X6luoJXdlbH2DEWDuRUf+8\n"
"X8FttGAfAnsQSyQReyCq8Lc9WwKBgQDarCRXmJvjJ/a1nk0WXLjKKjyxDGbZiW0A\n"
"mxDTdacu6Ez3OmG/TMGfbek4tXCxWdonXKrFS9mp2kpEx8CKpKiFU7EyVWDNXCde\n"
"8tvT2Zks3oKOXD2BbzVZRJn9DPeRv/nNrg6lfBHJJuTSHkzpx+vq0yTO0TcvOjv0\n"
"VRt1nKn4UQKBgQDBuACOZEnbdzwk9Z0Cc26RnnTHC1+Snf2xl/ggLGM8jbjH5bnC\n"
"q6/SnmXFB6WJX88xdZyzCgZ6v2RI6asCHb/ygQakPMg6DrCiD7/Vo1St+vbs6o2q\n"
"PrH9Vrt/iWS96ErYdEbe/sjX9u/L/dJ2FX03ON9ig9KwtnFOVf7QLyW4SQKBgQCs\n"
"o+2JTs38GEgZ+WHI/ulRiukhqrXkly/8o3A0UpXsXbCuG2SioJnZIfBYOj8/db3b\n"
"B7k3TPwKsnGiPcZQb1Ew+fNS1r83QsM+niRZ7FiXaRDQDhjtAHyw/o1IkJ1Ab71r\n"
"2jhsBDkSg2dyUEPO6mzil1JfCiQ0YBiHfU3RnB9BEQKBgEEGR3ZktG0NIEi378Rk\n"
"6nlnNesiNRxd6RJ12uAUhUdsio0c4b98IlP34/NvcjR0+e0G+ZpERMKYlh2P9h5c\n"
"cAPhVbVnnEbj1+ba/wZPmhBfs9EaDh377xmSLl2LEDr3M60UAw8+sJwnxSjit93H\n"
"XiMFS5kTl2kfKyQ20L6Q+eDU\n"
"-----END PRIVATE KEY-----\n";

using namespace easytls;

std::string readFile(const std::string& filename) 
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    return content;
}

void doHandshake(Server& ssl)
{
    int ret = 0;

    std::cout << "Waiting for TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));

        usleep(1000);
    }
    std::cout << "TLS handshake completed!" << std::endl;
}

int receiveData(Server& ssl)
{
    int ret = 0;
    unsigned char buffer[256];
    while (true) 
    {
        ret = ssl.read({ buffer, sizeof(buffer) - 1 });
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) 
        {
            usleep(1000);
            continue;
        }
        
        if (ret <= 0) 
        {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) 
                std::cout << "Client disconnected" << std::endl;

            break;
        }
        
        buffer[ret] = '\0';
        std::cout << "Received: " << buffer << std::endl;
        
        const char *response = "Message received over TLS/Unix socket";
        ssl.write({ (unsigned char *)response, strlen(response) });
    }

    return ret;
}


int main(int argc, char* argv[])
{
    SocketBio bio("/tmp/mbedtls-test.sock", true);
    auto debug = std::make_shared<CoutDebug>();
    Debug::setGlobal(debug);
    auto time = std::make_shared<TimeImpl>();
    Time::setGlobal(time);
    
    // auto serverCertData = readFile("test-server/server-cert.pem");
    // auto serverCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(serverCertData.c_str()), serverCertData.length() + 1 });
    
    // auto serverKeyData = readFile("test-server/server-key.pem");
    // auto serverKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(serverKeyData.c_str()), serverKeyData.length() + 1 });

    auto serverCert = easytls::x509::Certificate::parse(
        etl::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(certificatePem),
            sizeof(certificatePem)
        )
    );

    auto serverKey = easytls::PrivateKey::parse(
        etl::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(privateKeyPem),
            sizeof(privateKeyPem)
        )
    );

    if (not serverCert)
        throw std::runtime_error("Failed to parse server certificate. Status: " + std::to_string(x509::Certificate::getParseStatus()));
    
    if (not serverKey)
        throw std::runtime_error("Failed to parse server private key. Status: " + std::to_string(PrivateKey::getParseStatus()));
    
    Server tls(bio, "server", serverCert.value(), serverKey.value());

    if(not tls.isValid())
        throw std::runtime_error("Failed to create TLS server. Result: " + std::to_string(tls.getErrorCode()));

    tls.setDebug(Tls::DebugLevel::DEBUG);

    doHandshake(tls);
    auto ret = receiveData(tls);  

    if(ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        tls.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
	return ret;
}

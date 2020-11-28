#pragma once

#include "pch.h"

#include "NativeModules.h"

namespace RNAzureAuth {

    using winrt::Windows::Storage::Streams::IBuffer;
    using winrt::Windows::Security::Cryptography::BinaryStringEncoding;
    using winrt::Windows::Security::Cryptography::CryptographicBuffer;
    using winrt::Windows::Security::Cryptography::Core::HashAlgorithmProvider;
    using winrt::Windows::Security::Cryptography::Core::HashAlgorithmNames;

	REACT_STRUCT(OAuthParams);
	struct OAuthParams {
		REACT_FIELD(state, L"state");
		std::string state;
		REACT_FIELD(nonce, L"nonce");
		std::string nonce;
		REACT_FIELD(verifier, L"verifier");
		std::string verifier;
	};

	REACT_MODULE(AzureAuth);
	struct AzureAuth {

		REACT_CONSTANT_PROVIDER(GetConstants, L"getConstants");
		void GetConstants(winrt::Microsoft::ReactNative::ReactConstantProvider &constants) noexcept {
			constants.Add(L"bundleIdentifier", winrt::to_string(winrt::Windows::ApplicationModel::Package::Current().Id().Name()));
		}

		REACT_METHOD(OAuthParameters, L"oauthParameters");
		void OAuthParameters(const std::function<void(OAuthParams)>& resolve) noexcept
		{
			std::string state = winrt::to_string(randomDataBase64url(32));
			std::string nonce = winrt::to_string(randomDataBase64url(32));
			std::string verifier = winrt::to_string(randomDataBase64url(32));
			OAuthParams params = OAuthParams{ state, nonce, verifier };
			resolve(params);
		}

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        winrt::hstring randomDataBase64url(uint32_t length)
        {
            IBuffer buffer = CryptographicBuffer::GenerateRandom(length);
            return base64urlencodeNoPadding(buffer);
        }


        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputString"></param>
        /// <returns></returns>
        IBuffer sha256(winrt::param::hstring inputString)
        {
            HashAlgorithmProvider sha = HashAlgorithmProvider::OpenAlgorithm(HashAlgorithmNames::Sha256());
            IBuffer buff = CryptographicBuffer::ConvertStringToBinary(inputString, BinaryStringEncoding::Utf8);
            return sha.HashData(buff);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        winrt::hstring base64urlencodeNoPadding(IBuffer buffer)
        {
            winrt::hstring base64 = CryptographicBuffer::EncodeToBase64String(buffer);

            std::string b = winrt::to_string(base64);
            // Converts base64 to base64url.
            b = std::regex_replace(b, std::regex("\+"), "-");
            b = std::regex_replace(b, std::regex("\/"), "_");
            // Strips padding.
            b = std::regex_replace(b, std::regex("="), "");
            // Converts base64 to base64url.
            base64 = winrt::to_hstring(b);

            return base64;
        }
	};
}

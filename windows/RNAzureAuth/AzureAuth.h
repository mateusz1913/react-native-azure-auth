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
			std::string state = randomDataBase64url(32);
			std::string nonce = randomDataBase64url(32);
			std::string verifier = randomDataBase64url(32);
			OAuthParams params = OAuthParams{ state, nonce, verifier };
			resolve(params);
		}

		std::string randomDataBase64url(uint32_t length)
		{
			IBuffer buffer = CryptographicBuffer::GenerateRandom(length);
			std::string base64 = winrt::to_string(CryptographicBuffer::EncodeToBase64String(buffer));
			std::replace(base64.begin(), base64.end(), '+', '-');
			std::replace(base64.begin(), base64.end(), '/', '_');
			base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());
			return base64;
		}
	};
}

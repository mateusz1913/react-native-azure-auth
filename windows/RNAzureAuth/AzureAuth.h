#pragma once

#include "pch.h"

#include "NativeModules.h"

namespace RNAzureAuth {

	using winrt::Windows::Foundation::Uri;
    using winrt::Windows::Storage::Streams::IBuffer;
    using winrt::Windows::Security::Cryptography::BinaryStringEncoding;
    using winrt::Windows::Security::Cryptography::CryptographicBuffer;
    using winrt::Windows::Security::Cryptography::Core::HashAlgorithmProvider;
    using winrt::Windows::Security::Cryptography::Core::HashAlgorithmNames;

	REACT_STRUCT(OAuthParams);
	struct OAuthParams
	{
		REACT_FIELD(state, L"state");
		std::string state;
		REACT_FIELD(nonce, L"nonce");
		std::string nonce;
		REACT_FIELD(verifier, L"verifier");
		std::string verifier;
	};

	REACT_MODULE(AzureAuth);
	struct AzureAuth : public std::enable_shared_from_this<AzureAuth> {

		winrt::Microsoft::ReactNative::ReactContext m_context;
		std::function<void(JSValue)> callback;
		bool closeOnLoad;

		REACT_INIT(Initialize, L"Initialize");
		void Initialize(winrt::Microsoft::ReactNative::ReactContext const& reactContext) noexcept
		{
			if (auto app = xaml::TryGetCurrentApplication())
			{
				app.Resuming(
					winrt::auto_revoke,
					[weakThis = weak_from_this()](
						winrt::IInspectable const& /*sender*/,
						winrt::Windows::ApplicationModel::EnteredBackgroundEventArgs const& /*e*/) noexcept {
					if (auto strongThis = weakThis.lock())
					{
						if (strongThis->callback != nullptr)
						{
							if (strongThis->closeOnLoad)
							{
								strongThis->callback(JSValue{});
							}
							else
							{
								strongThis->callback(strongThis->createError("a0.session.user_cancelled", "User cancelled the Auth"));
							}
							strongThis->callback = nullptr;
							strongThis->closeOnLoad = false;
						}
					}
				});
			}
		}

		REACT_CONSTANT_PROVIDER(GetConstants, L"getConstants");
		void GetConstants(winrt::Microsoft::ReactNative::ReactConstantProvider &constants) noexcept
		{
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

		REACT_METHOD(hide, L"hide");
		void hide() noexcept
		{
			this->callback = nullptr;
			this->closeOnLoad = false;
		}

		REACT_METHOD(showUrl, L"showUrl");
		void showUrl(std::string urlString, bool closeOnLoad, const std::function<void(JSValue)>& callback) noexcept
		{
			this->callback = callback;
			this->closeOnLoad = closeOnLoad;
			auto success = winrt::Windows::System::Launcher::LaunchUriAsync(Uri(winrt::to_hstring(urlString)));
			success.Completed([this](bool result)
				{
					if (!result)
					{
						this->callback(createError("a0.session.failed_load", "Failed to load url"));
					}
				}
			);
		}

		JSValue createError(std::string error, std::string errorDescription) noexcept
		{
			JSValueObject obj = JSValueObject{};
			obj["error"] = error;
			obj["error_description"] = errorDescription;
			return std::move(obj);
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

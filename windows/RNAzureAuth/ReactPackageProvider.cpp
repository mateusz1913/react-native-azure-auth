#include "pch.h"
#include "ReactPackageProvider.h"
#include "ReactPackageProvider.g.cpp"

#include "AzureAuth.h"

namespace winrt::RNAzureAuth::implementation {
	void ReactPackageProvider::CreatePackage(IReactPackageBuilder const& packageBuilder) noexcept
	{
		AddAttributedModules(packageBuilder);
	}
}
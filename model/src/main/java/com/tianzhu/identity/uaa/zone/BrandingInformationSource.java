package com.tianzhu.identity.uaa.zone;

import com.tianzhu.identity.uaa.zone.BrandingInformation.Banner;

import java.util.Map;

public interface BrandingInformationSource {
    Banner getBanner();

    String getCompanyName();

    String getProductLogo();

    String getSquareLogo();

    String getFooterLegalText();

    Map<String, String> getFooterLinks();
}

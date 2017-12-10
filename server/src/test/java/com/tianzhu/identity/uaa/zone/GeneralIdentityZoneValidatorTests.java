package com.tianzhu.identity.uaa.zone;


import org.junit.Test;

import java.util.Arrays;

import static com.tianzhu.identity.uaa.zone.IdentityZoneValidator.Mode.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.*;

public class GeneralIdentityZoneValidatorTests {


    GeneralIdentityZoneConfigurationValidator zoneConfigurationValidator = mock(GeneralIdentityZoneConfigurationValidator.class);
    GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(zoneConfigurationValidator);

    @Test
    public void validate_right_mode() throws InvalidIdentityZoneDetailsException, InvalidIdentityZoneConfigurationException {
        IdentityZone zone = MultitenancyFixture.identityZone("id", "domain");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        zone.setConfig(config);
        for (IdentityZoneValidator.Mode  mode : Arrays.asList(CREATE, MODIFY, DELETE)) {
            reset(zoneConfigurationValidator);
            when(zoneConfigurationValidator.validate(any(), any())).thenReturn(config);
            validator.validate(zone, mode);
            verify(zoneConfigurationValidator, times(1)).validate(same(zone), same(mode));
        }
    }
}

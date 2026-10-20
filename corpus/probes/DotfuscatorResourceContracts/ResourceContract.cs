using System.Resources;

[assembly: SatelliteContractVersion("1.0.0.0")]
#if SATELLITE_ONLY
[assembly: NeutralResourcesLanguage("fr", UltimateResourceFallbackLocation.Satellite)]
#endif

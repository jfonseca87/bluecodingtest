using Microsoft.AspNetCore.Mvc;
using ClimateMonitor.Services;
using ClimateMonitor.Services.Models;
using System.Text.RegularExpressions;

namespace ClimateMonitor.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class ReadingsController : ControllerBase
{
    private readonly DeviceSecretValidatorService _secretValidator;
    private readonly AlertService _alertService;
    private readonly string _firwareRegexPattern;

    public ReadingsController(
        DeviceSecretValidatorService secretValidator,
        AlertService alertService)
    {
        _secretValidator = secretValidator;
        _alertService = alertService;
        _firwareRegexPattern = "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$";
    }

    /// <summary>
    /// Evaluate a sensor readings from a device and return possible alerts.
    /// </summary>
    /// <remarks>
    /// The endpoint receives sensor readings (temperature, humidity) values
    /// as well as some extra metadata (firmwareVersion), evaluates the values
    /// and generate the possible alerts the values can raise.
    /// 
    /// There are old device out there, and if they get a firmwareVersion 
    /// format error they will request a firmware update to another service.
    /// </remarks>
    /// <param name="deviceSecret">A unique identifier on the device included in the header(x-device-shared-secret).</param>
    /// <param name="deviceReadingRequest">Sensor information and extra metadata from device.</param>
    [HttpPost("evaluate")]
    public ActionResult<IEnumerable<Alert>> EvaluateReading(
        [FromBody] DeviceReadingRequest deviceReadingRequest)
    {
        string deviceSecret = HttpContext.Request.Headers["x-device-shared-secret"];
        bool isValidFirmware = Regex.IsMatch(deviceReadingRequest.FirmwareVersion, _firwareRegexPattern);

        if (!isValidFirmware)
        {
            var validationProblemDetails = new ValidationProblemDetails();
            validationProblemDetails.Errors.Add("FirmwareVersion", new string[] { "The firmware value does not match semantic versioning format." });
            return BadRequest(validationProblemDetails);
        }

        if (!_secretValidator.ValidateDeviceSecret(deviceSecret))
        {
            return Problem(
                detail: "Device secret is not within the valid range.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return Ok(_alertService.GetAlerts(deviceReadingRequest));
    }
}

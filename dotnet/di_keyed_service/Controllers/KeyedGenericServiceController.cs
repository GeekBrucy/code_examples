using di_keyed_service.Models;
using di_keyed_service.Services._02_Generic;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class KeyedGenericServiceController : ControllerBase
    {
        private readonly IServiceProvider _serviceProvider;
        public KeyedGenericServiceController(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }
        [HttpGet]
        public IActionResult TestGenericServices()
        {
            var sampleModel = new SampleModel
            {
                MyProperty1 = "Hello World",
                MyProperty2 = 42,
                MyProperty3 = new int[] { 1, 2, 3 },
                MyProperty4 = true
            };

            var properties = sampleModel.GetType().GetProperties();
            var processedServices = new List<string>();

            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(sampleModel);
                var service = _serviceProvider.GetKeyedService<IGenericBaseService>(property.Name);

                if (service != null)
                {
                    service.RunGeneric(propertyValue);
                    processedServices.Add(property.Name);
                }
            }

            return Ok(new
            {
                Message = "Keyed generic services executed successfully",
                ProcessedProperties = processedServices
            });
        }
    }
}
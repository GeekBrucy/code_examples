using di_keyed_service.Models;
using di_keyed_service.Services._02_Generic;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class GenericServiceController : ControllerBase
    {
        private readonly IEnumerable<IGenericBaseService> _genericBaseServices;

        public GenericServiceController(IEnumerable<IGenericBaseService> genericBaseServices)
        {
            _genericBaseServices = genericBaseServices;
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
                var matchingService = _genericBaseServices.FirstOrDefault(s => s.Key == property.Name);
                
                if (matchingService != null)
                {
                    matchingService.RunGeneric(propertyValue);
                    processedServices.Add(property.Name);
                }
            }
            
            return Ok(new { 
                Message = "Generic services executed successfully", 
                ProcessedProperties = processedServices 
            });
        }
    }
}
using di_keyed_service.Models;
using di_keyed_service.Services._03_PropertyProcessor;
using Microsoft.AspNetCore.Mvc;

namespace di_keyed_service.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class PropertyProcessorController : ControllerBase
    {
        private readonly IServiceProvider _serviceProvider;

        public PropertyProcessorController(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        [HttpGet]
        public IActionResult TestPropertyProcessors()
        {
            var sampleModel = new SampleModel
            {
                MyProperty1 = "Hello from Property Processor!",
                MyProperty2 = 100,
                MyProperty3 = new int[] { 10, 20, 30, 40 },
                MyProperty4 = false
            };
            
            var properties = sampleModel.GetType().GetProperties();
            var processedProperties = new List<string>();
            
            foreach (var property in properties)
            {
                var propertyValue = property.GetValue(sampleModel);
                var processor = _serviceProvider.GetKeyedService<IPropertyProcessor>(property.Name);
                
                if (processor?.CanProcess(property.Name) == true)
                {
                    processor.ProcessProperty(property.Name, propertyValue);
                    processedProperties.Add(property.Name);
                }
            }
            
            return Ok(new { 
                Message = "Property processors executed successfully", 
                ProcessedProperties = processedProperties,
                Approach = "Option 3: Property Processor Pattern - Clean interface without generics"
            });
        }
    }
}
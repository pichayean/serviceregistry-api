using JsonFlatFileDataStore;
using service_register;
public interface IServiceRegisterService
{
    IEnumerable<ServiceRegistration> Get();
    ServiceRegistration Get(int id);
    Task<ServiceRegistration> UpdateAsync(ServiceRegistration model);
    Task<bool> CreateAsync(ServiceRegistration model);
    Task<bool> DeleteAsync(int id);
}

public class ServiceRegisterService : IServiceRegisterService
{
    public readonly IDocumentCollection<ServiceRegistration> _collection;

    public ServiceRegisterService()
    {
        var store = new DataStore("data.json");
        _collection = store.GetCollection<ServiceRegistration>();
    }

    public ServiceRegistration Get(int id)
    {
        var response = _collection.AsQueryable().FirstOrDefault(_ => _.Id == id);
        if (response == null)
            throw new Exception("Data not found!");
        return response;
    }

    public IEnumerable<ServiceRegistration> Get()
    {
        return _collection.AsQueryable().ToList();
    }

    public async Task<ServiceRegistration> UpdateAsync(ServiceRegistration model)
    {
        var updateModel = _collection.AsQueryable().FirstOrDefault(_ => _.Id == model.Id);
        if (updateModel == null)
            throw new Exception("Data not found!");
        await _collection.UpdateOneAsync(updateModel.Id, updateModel);

        return updateModel;
    }

    public async Task<bool> CreateAsync(ServiceRegistration model)
    {
        return await _collection.InsertOneAsync(model);
    }

    public async Task<bool> DeleteAsync(int id)
    {
        return await _collection.DeleteOneAsync(e => e.Id == id);
    }
}

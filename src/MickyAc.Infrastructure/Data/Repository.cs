using System.Linq.Expressions;
using MickyAc.Domain.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace MickyAc.Infrastructure.Data;

public class Repository<T> : IRepository<T> where T : class
{
    protected readonly ForensicDbContext Context;
    protected readonly DbSet<T> DbSet;

    public Repository(ForensicDbContext context)
    {
        Context = context;
        DbSet = context.Set<T>();
    }

    public async Task<T?> GetByIdAsync(string id)
    {
        return await DbSet.FindAsync(id);
    }

    public async Task<List<T>> GetAllAsync()
    {
        return await DbSet.ToListAsync();
    }

    public async Task<List<T>> FindAsync(Expression<Func<T, bool>> predicate)
    {
        return await DbSet.Where(predicate).ToListAsync();
    }

    public async Task AddAsync(T entity)
    {
        await DbSet.AddAsync(entity);
        await Context.SaveChangesAsync();
    }

    public async Task AddRangeAsync(IEnumerable<T> entities)
    {
        await DbSet.AddRangeAsync(entities);
        await Context.SaveChangesAsync();
    }

    public async Task UpdateAsync(T entity)
    {
        DbSet.Update(entity);
        await Context.SaveChangesAsync();
    }

    public async Task DeleteAsync(string id)
    {
        var entity = await DbSet.FindAsync(id);
        if (entity is not null)
        {
            DbSet.Remove(entity);
            await Context.SaveChangesAsync();
        }
    }

    public async Task<int> CountAsync()
    {
        return await DbSet.CountAsync();
    }

    public async Task<int> CountAsync(Expression<Func<T, bool>> predicate)
    {
        return await DbSet.CountAsync(predicate);
    }
}

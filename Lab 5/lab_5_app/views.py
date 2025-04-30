from django.shortcuts import render, get_object_or_404, redirect
from .models import Entity

# Фіксовані дані для першої частини лабораторної
FIXED_DATA = [
    {"id": 1, "name": "Об'єкт 1", "description": "Опис об'єкта 1"},
    {"id": 2, "name": "Об'єкт 2", "description": "Опис об'єкта 2"},
]

def index(request):
    return render(request, 'lab_5_app/index.html')

def entity_list(request):
    # Для першої частини лабораторної
    if not Entity.objects.exists():
        context = {'entities': FIXED_DATA}
    else:
        context = {'entities': Entity.objects.all()}
    return render(request, 'lab_5_app/entity_list.html', context)

def entity_detail(request, pk):
    # Для першої частини лабораторної
    if not Entity.objects.exists():
        entity = next((item for item in FIXED_DATA if item["id"] == pk), None)
        if not entity:
            raise Http404("Об'єкт не знайдено")
    else:
        entity = get_object_or_404(Entity, pk=pk)
    return render(request, 'lab_5_app/entity_detail.html', {'entity': entity})

# CRUD операції для другої частини лабораторної
def entity_create(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description')
        Entity.objects.create(name=name, description=description)
        return redirect('entity_list')
    return render(request, 'lab_5_app/entity_form.html')

def entity_update(request, pk):
    entity = get_object_or_404(Entity, pk=pk)
    if request.method == 'POST':
        entity.name = request.POST.get('name')
        entity.description = request.POST.get('description')
        entity.save()
        return redirect('entity_detail', pk=entity.pk)
    return render(request, 'lab_5_app/entity_form.html', {'entity': entity})

def entity_delete(request, pk):
    entity = get_object_or_404(Entity, pk=pk)
    if request.method == 'POST':
        entity.delete()
        return redirect('entity_list')
    return render(request, 'lab_5_app/entity_confirm_delete.html', {'entity': entity})
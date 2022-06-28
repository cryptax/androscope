from django.http import HttpResponse, HttpResponseRedirect
from django.db import IntegrityError
from django.shortcuts import render
from django.urls import reverse
from django.views.generic import ListView
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.exceptions import PermissionDenied
from django.contrib import messages
from .forms import CaptchaForm, SelectForm, SearchForm, InsertForm
from .models import Malware, Property, MalwareName
from .android import *


import datetime
import logging

logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def about(request):
    return render(request, 'about.html')

def index(request):
    return render(request, 'index.html')

def pretty_request(request):
    headers = ''
    for header, value in request.META.items():
        if not header.startswith('HTTP'):
            continue
        header = '-'.join([h.capitalize() for h in header[5:].lower().split('_')])
        headers += '{}: {}\n'.format(header, value)

    return (
        '{method} HTTP/1.1\n'
        'Content-Length: {content_length}\n'
        'Content-Type: {content_type}\n'
        '{headers}\n\n'
        '{body}'
    ).format(
        method=request.method,
        content_length=request.META['CONTENT_LENGTH'],
        content_type=request.META['CONTENT_TYPE'],
        headers=headers,
        body=request.body,
    )

def get_malware(sha256):
    malware_list = Malware.objects.filter(sha256=sha256)
    nb = len(malware_list)
    if nb > 1:
        logger.error("get_malware(): we have {} entries for the same sha256. This should not happen! sha256={}".format(nb, sha256))
        return malware_list[0]

    if nb == 0:
        logger.warning("get_malware(): we couldnt find this sha256={}".format(sha256))
        return None

    #logger.debug("get_malware(): ok")
    return malware_list[0]

    

def mark_checked(sha256, to_check=False):
    m = get_malware(sha256)
    if m != None:
        m.to_check = to_check
        m.save()
        logger.debug("mark_checked(): OK  for sha256={}".format(sha256))
        

def view(request):
    '''
    Displays all malware in the database, paginated.
    '''
    if request.method == 'POST':
        for posted_item in request.POST.keys():
            if posted_item != 'csrfmiddlewaretoken' and request.POST[posted_item].lower() == 'false':
                logger.debug("view(): we reviewed sha256={} to_check={}".format(posted_item, request.POST[posted_item]))
                mark_checked(posted_item)

    malware_list = Malware.objects.all()
    reviewer = False
    if belongs_to_group(request.user, 'reviewer'):
        message = 'You are a reviewer. When you have time, please consider checking samples which require reviewer validation: inspect their properties, edit if necessary, and finally mark as checked.'
        reviewer = True
    else:
        message = 'Androscope does not store any sample, only their hashes and reverse engineering information'
    page_list = paginate(request, malware_list)

    # The view displays fields from the Malware object and general_name from the Property object
    # So, we re-construct a custom results list including that info
    results = []
    for m in page_list:
        query_p = Property.objects.filter(sha256=m.sha256)
        prop = None
        if len(query_p) == 0:
            logger.warning("view(): fixing case with no property sha256={}".format(m.sha256))
            prop = Property(sha256=m.sha256,general_name='Unknown')
            prop.save()
        else:
            prop = query_p[0]

        #logger.debug("view(): sha256={} general_name={}".format(m.sha256, prop.general_name))
        mn = MalwareName(malware=m, general_name=prop.general_name)
        results.append(mn)
        
    context = { 'query_results' : results, 'message' : message, 'reviewer' :  reviewer }
    return render(request, 'view.html', context)


def paginate(request, object_list, nb_per_page=20):
    '''
    Paginates an HTTP request to display a page of nb_per_page objects from the object_list
    request may have a 'page' field
    '''
    pagenum = request.GET.get('page', 1)
    paginator = Paginator(object_list, nb_per_page)
    try:
        page_list = paginator.page(pagenum)
    except PageNotAnInteger:
        page_list = paginator.page(1)
    except EmptyPage:
        page_list = paginator.page(paginator.num_pages)

    logger.debug("paginate(): pagenum={}".format(pagenum))
    return page_list


def captcha(request):
    '''
    If the captcha is solved, this method is expected to insert a captcha indicator in the session
    and redirect to either upload or insert
    If the captcha is wrong an error message is displayed
    '''
    message = 'Please solve the captcha to upload a sample'
    
    if request.method == 'POST':
        form = CaptchaForm(request.POST)
        if form.is_valid():
            logger.debug("captcha(): captcha OK")
            request.session['captcha'] = True
            if 'nextstep' in request.session and request.session['nextstep'] == 'upload':
                logger.debug("captcha() --> upload()")
                return HttpResponseRedirect(reverse('upload'))
            else:
                request.session['nextstep'] = 'insert'
                logger.debug("captcha() --> insert()")
                return HttpResponseRedirect(reverse('insert'))
            
        else:
            logger.warning("captcha() is invalid: errors={}".format(form.errors))
            return render(request, 'captcha.html', { 'form' : form, 'message' : 'Invalid captcha !' })
    else:
        if 'nextstep' in request.GET:
            # default value is insert
            request.session['nextstep'] = request.GET.get('nextstep', 'insert')
            logger.debug("captcha(): setting nextstep={}".format(request.session['nextstep']))
            if request.session['nextstep'] == 'insert':
                message = 'Please solve the captcha to insert a sample'
            
        form = CaptchaForm()

    return render(request, 'captcha.html', {'form' : form, 'message' : message} )

def insert(request):
    if not is_captcha_solved(request, 'insert'):
        return HttpResponseRedirect('captcha.html?nextstep=insert')

    if request.method == 'POST':
        form = InsertForm(request.POST)
        if form.is_valid():
            sha256 = form.cleaned_data['sha256']
            logger.debug("insert(): form is valid - sha256={}".format(sha256))
            file_sha256, success, msg = save_malware(sha256, 'inserted-by-sha256', insertion_date=datetime.date.today(), user=request.user)
            del request.session['captcha']
            if success:
                return HttpResponseRedirect(reverse('select', args=(sha256,)))
            else:    
                logger.warning("insert(): sample already exists - sha256={}".format(sha256))
                return render(request, 'insert.html', { 'insert_message' : msg })
        else:
            logger.warning("insert(): invalid form")
            return render(request, 'insert.html', { 'form' : form })

    else:
        logger.debug("insert(): show the form")
        form = InsertForm()

    return render(request, 'insert.html', { 'form' : form })


def upload(request):
    '''
    If captcha is not solved yet -> go to captcha
    Display a form to upload a sample --> upload with GET
    When the file is posted (upload with POST), check the file is an APK/DEX + sample is known to VirusTotal/Koodous/Pithus.
    If not APK/DEX --> display an error message
    If not known --> display a confirmation message asking if you really want to upload
    If the sample is known --> forward to select()
    If the unknown sample is confirmed --> forward to select()
    If the unknown sample is not confirmed --> abandon

    When forwarding to select, select expects to find a temporary file to analyze + filetype
    '''
    if not is_captcha_solved(request):
        return HttpResponseRedirect('captcha.html?nextstep=upload')

    if request.method == 'POST':
        if request.FILES:
            logger.debug("upload(): a file has been dropped for upload")
            file_sha256, filetype, known, msg = handle_uploaded_file(request.FILES['file'], request.user)
            
            if known:
                logger.debug("upload(): known malware - successful file upload - sha256={}".format(file_sha256))
                request.session['upload_tmpname'] = write_tmp_file(request.FILES['file'])
                request.session['upload_filetype'] = filetype
                del request.session['captcha']
                save_malware(file_sha256, filename=request.FILES['file'].name, insertion_date=datetime.date.today(), user=request.user)
                return HttpResponseRedirect(reverse('select', args=(file_sha256, )))
            else:
                if 'confirm' in msg:
                    logger.debug("upload(): unknown sample - displaying confirmation message")
                    request.session['upload_sha256'] = file_sha256
                    request.session['upload_filename'] = request.FILES['file'].name
                    request.session['upload_tmpname'] = write_tmp_file(request.FILES['file'])
                    request.session['upload_filetype'] = filetype
                    return render(request, 'upload.html', { 'confirm_message' : msg })
                else:
                    logger.warning("upload(): displaying error message")
                    return render(request, 'upload.html', { 'upload_message' : msg, 'confirm_message' : '' })

        elif 'upload_sha256' in request.session:
            file_sha256 = request.session['upload_sha256']
            del request.session['upload_sha256']

            if handle_confirmation_choice(request, file_sha256) == 'cancel':
                return render(request, 'upload.html', { 'confirm_message' : '' })
            else:
                return HttpResponseRedirect(reverse('select', args=(file_sha256, )))
        
    logger.debug("upload(): default case -> show the upload template")
    return render(request, 'upload.html', { 'confirm_message' : '' } )

def is_captcha_solved(request, nextstep='upload'):
    if 'nextstep' not in request.session or 'captcha' not in request.session:
        logger.warning("is_captcha_solved(): missing nextstep or captcha")
        return False

    if request.session['nextstep'] != nextstep or request.session['captcha'] != True:
        logger.warning("is_captcha_solved(): wrong value: nextstep={} captcha={}".format(request.session['nextstep'], request.session['captcha']))
        return False

    logger.debug("is_captcha_solved(): ok")
    return True

def handle_confirmation_choice(request, file_sha256):
    if 'upload_filename' not in request.session:
        logger.error('handle_confirmation_choice(): upload_filename is missing')
        return 'error'
    
    filename = request.session['upload_filename']
    del request.session['upload_filename']

    if request.POST['choice'] != 'cancel':
        logger.debug("handle_confirmation_choice(): upload was confirmed")
        if 'captcha' in request.session:
            del request.session['captcha']
        save_malware(file_sha256, filename=filename, insertion_date=datetime.date.today(), user=request.user)
    else:
        logger.debug("handle_confirmation_choice(): upload was cancelled")

    return request.POST['choice']
        

def handle_uploaded_file(f, user):
    logger.debug("handle_uploaded_file(): filename={} user={}".format(f.name, user))
    msg = ''
    digest = compute_sha256(f)
    filetype = get_type(f)
    
    if filetype == Filetype.UNKNOWN:
        logger.warning("handle_uploaded_file(): this is not an Android app")
        return digest, filetype, False, 'This is not an Android sample'
    elif filetype == Filetype.JAR or filetype == Filetype.ZIP:
        if not is_dex_inside(f):
            logger.warning("handle_uploaded_file(): this zip contains no dex")
            return digest, filetype, False, 'This is not an Android sample'

    if not search_pithus(digest) and not search_koodous(digest) and not search_malwarebazaar(digest):
        logger.warning("handle_uploaded_file(): checking sample in VT")
        vt_json = search_virustotal(digest)
        if vt_json == None:
            logger.warning("handle_uploaded_file(): sample not present in Pithus, Koodous, Malware Bazaar, VT. Is this a malicious sample?")
            return digest, filetype, False, 'This sample is unknown to VirusTotal, Koodous, Malware Bazaar, Pithus. Do you confirm it is malicious?'

    digest, success, msg = save_malware(digest, filename=f.name, insertion_date=datetime.date.today(), user=user)
    return digest, filetype, success, msg

def belongs_to_group(user, group_name='poweruser'):
    status = user.groups.filter(name=group_name).exists()
    logger.debug("belongs_to_group(): user={} group={}: {}".format(user, group_name, status))
    return status

def save_malware(sha256, filename, insertion_date, user):
    if belongs_to_group(user, 'poweruser') or belongs_to_group(user, 'reviewer'):
        m = Malware(sha256=sha256, filename=filename, insertion_date=insertion_date, to_check=False)
    else:
        m = Malware(sha256=sha256, filename=filename, insertion_date=insertion_date, to_check=True)
        
    try:
        m.save()
    except IntegrityError as e:
        logger.warning("save_malware(): integrity e={}".format(e))
        return sha256, False, 'This file already exists'

    logger.debug("save_malware(): OK - sha256={} filename={} date={}".format(sha256, filename, insertion_date))
    return sha256, True, ''
    

# This handles urls that look like /select/<sha256...>
def select(request, file_sha256):
    '''
    Property selection is requested for 
    - upload: try and pre-fill properties by analyzing it. Expects upload_tmpname and upload_filetype
    - insert: impossible to pre-fill as we don't have the sample! Except its name.
    '''
    p = Property.objects.filter(sha256=file_sha256)
    if len(p) > 0:
        logger.warning("select(): property for this sha256 already exists (database inconsistency - we overwrite the values")
        form, validity = select_form(request, p[0])
    else:
        form, validity = select_form(request)
        
    if validity:
        # property form has been submitted --> redirect to view() where we show all malware
        prop = form.save(commit=False)
        prop.sha256 = file_sha256
        prop.username = request.user.username
        logger.debug("select(): property={}".format(prop))
        prop.save()
        return HttpResponseRedirect(reverse('view'))

    prefilled_features = []
    initial = {}
    if 'upload_tmpname' in request.session and request.session['upload_tmpname']:
        filename = ''
        if 'upload_filetype' in request.session and (request.session['upload_filetype'] == Filetype.JAR or request.session['upload_filetype'] == Filetype.ZIP):
            logger.debug("select(): unzipping...")
            filename = unzip_apk(request.session['upload_tmpname'])

        if 'upload_filetype' in request.session and request.session['upload_filetype'] == Filetype.DEX:
            filename = request.session['upload_tmpname']

        if filename != '':
            logger.debug("select(): analyzing {} to get suggested features".format(filename))
            initial, prefilled_features = suggest_from_dex(filename)

        if os.path.exists(request.session['upload_tmpname']):
            os.remove(request.session['upload_tmpname'])
        else:
            logger.warning("select(): {} has already been removed?".format(request.session['upload_tmpname']))
        del request.session['upload_tmpname']
    
    # get potential name
    vtotal_json = search_virustotal(file_sha256)
    if vtotal_json != None:
        suggested_names = get_virustotal_names(vtotal_json)
        initial['general_name'] = suggested_names
        prefilled_features.append("Malware name (category: Main)")

    # load form with pre-filled values
    logger.debug("select(): initial={}".format(initial))
    form = SelectForm(initial = initial)

    listm = Malware.objects.filter(sha256=file_sha256)
    if len(listm) > 0:
        m = listm[0]
    else:
        # something is wrong - we're editing properties on a non-existent malware ?!
        logger.error("select(): could not find Malware object for this file")
        # we might want to display an error to the user?
        return HttpResponseRedirect(reverse('index'))

    # show the select form
    context = { 'sample' : m, 'form' : form, 'toggle_categories' : get_toggle_categories(), 'message' : 'Select malicious features the malware implements. When you dont know, leave blank. ', 'prefilled_features' : prefilled_features }

    logger.debug("select(): rendering select form")
    return render(request, 'select.html', context)

def search(request):
    '''
    Search for malware based on given criteria.

    1) Display a form of criterial to select 
        GET /search --> select.html
    2) Post and validate this form
        POST /search with form data
    3) Search for matching results and display them paginated
        --> display search.html with one page of results
        if the user wants another page: GET /search?page=x

        The search criteria are saved in the request session. They are erased if no page number is provided.
    '''
    if request.method == 'POST':
        form = SearchForm(request.POST)
        if form.is_valid():
            logger.debug("search(): form is valid")
            # the form is valid, we search for malware which match the query. Queryset contains all matches.
            queryset = perform_search(form.cleaned_data)
            # we only display one page of data. page_list contains 1 page of data.
            page_list = paginate(request, queryset)
            '''
            We need to store the query for future pages.
            It is easier to store the query (precisely the cleaned form) than the results (a Query Set)
            because QuerySets need to be serialized, and then deserialized (actually, deserializing is the issue)
            '''
            request.session['search_query'] = form.cleaned_data
            logger.debug("search(): showing one page of data")
            return render(request, 'search.html', { 'malware_list' : page_list })
        else:
            logger.warning("search(): form is INVALID! Errors: {}".format(form.errors))
            context = { 'form' : form, 'toggle_categories' : get_toggle_categories(), 'message' : '' }
            return render(request, 'select.html', context)
        
    elif request.method == 'GET' and 'search_query' in request.session:
        if 'page' in request.GET:
            logger.debug("search(): GET page")
            queryset = perform_search( request.session.get('search_query') )
            page_list = paginate(request, queryset)
            return render(request, 'search.html', { 'malware_list' : page_list })
        else:
            logger.debug("search(): Erase search_query")
            del request.session['search_query']
        

    # we use the generic select form to get fields we want to search for
    form = SearchForm()
    context = { 'form' : form, 'toggle_categories' : get_toggle_categories(), 'title' : 'Search Androscope for malware', 'mode' : 'search' }
    logger.debug("search(): rendering select")
    return render(request, 'select.html', context)

def select_form(request, record=None):
    # record: the record to edit
    logger.debug("select_form(): request.method={} record={}".format(request.method, record))
    if request.method == 'POST':
        if record is not None:
            logger.debug("select_form() with POST+record")
            form = SelectForm(request.POST, instance=record)
        else:
            logger.debug("select_form() with POST")
            form = SelectForm(request.POST)
            
        if form.is_valid():
            logger.debug("select_form(): Form is valid. Cleaned data={}".format(form.cleaned_data))
            return form, True
        else:
            logger.warning("select_form(): Form is not valid! Errors: {}".format(form.errors))

    else:
        # we need to display the form
        if record is not None:
            logger.debug("select_form(): SelectForm for record={}".format(record))
            form = SelectForm(instance=record)
        else:
            logger.debug("select_form(): empty default form")
            form = SelectForm()

    return form, False
    

def get_toggle_categories():
    return [ { 'color' : 'androred', 'name' : 'collapseMain', 'label' : 'Main' },
             { 'color' : 'androred', 'name' : 'collapseSms', 'label' : 'SMS' },
             { 'color' : 'androred', 'name' : 'collapseCalls', 'label' : 'Phone calls' },
             { 'color' : 'androred', 'name' : 'collapsePrivacy', 'label' : 'Privacy' },
             { 'color' : 'androred', 'name' : 'collapseNetwork', 'label' : 'Network' },
            { 'color' : 'androred', 'name' : 'collapsePacker', 'label' : 'Packing' },
             { 'color' : 'androred', 'name' : 'collapseObfuscation', 'label' : 'Obfuscation' },
             { 'color' : 'androred', 'name' : 'collapseNative', 'label' : 'Native' },
            { 'color' : 'androred', 'name' : 'collapseAnti', 'label' : 'Anti-reversing' },
             { 'color' : 'androred', 'name' : 'collapseLang', 'label' : 'Language' } ]

def perform_search(search_form):
    queryset = Property.objects.all()

    # handling boolean fields only
    for field in search_form.keys():
        
        
        if not 'other' in field and not 'common2' in field and not '_name' in field and not 'sha256' in field and search_form[field]:
            kwargs = {
                '{0}'.format(field): True
            }
            queryset = queryset.filter(**kwargs)
            logger.debug("perform_search(): Filtering boolean field {}=True".format(field))

        if (field == 'packer_name' and search_form['packer_yes'] and search_form['packer_name'] != 'unknown') or \
            (field == 'obfuscation_name' and search_form['obfuscation_yes'] and search_form['obfuscation_name'] != 'unknown'):
            kwargs = {
                '{0}'.format(field): search_form[field]
            }
            queryset = queryset.filter(**kwargs)
            logger.debug("perform_search(): Filtering names {}='{}'".format(field, search_form[field]))

        if ('other' in field or 'common2' in field or 'sha256' in field or 'general_name' in field) and search_form[field] != '':
            kwargs = {
                '{0}__contains'.format(field): search_form[field]
            }
            logger.debug("Current queryset={}".format(queryset))
            logger.debug("perform_search(): kwargs={}".format(kwargs))
            queryset = queryset.filter(**kwargs)
            logger.debug("perform_search(): Filtering keywords {} contains {}".format(field, search_form[field]))

    # check malware of the query set are validated
    unchecked = []
    for p in queryset:
        m = get_malware(p.sha256)
        if m == None or m.to_check == True:
            unchecked.append(p.sha256)
            #logger.debug("perform_search(): Remove {}".format(p.sha256))

    for u in unchecked:
        logger.debug("perform_search(): removing unchecked entry sha256={}".format(u))
        queryset = queryset.exclude(sha256=u)

    # dumping the queryset
    logger.debug("perform_search(): ------ DUMPING ----")
    for p in queryset:
        logger.debug("perform_search(): match: sha256={}".format(p.sha256))
    logger.debug("perform_search(): ------ DUMPING ----")
    
    return queryset

def show(request, file_sha256):
    p_queryset = Property.objects.filter(sha256=file_sha256)
    m_queryset = Malware.objects.filter(sha256=file_sha256)

    if len(p_queryset) == 0:
        logger.warning("show(): no properties for sha256={}".format(file_sha256))
        prop = Property(sha256=file_sha256)
        prop.save()
        p_queryset = Property.objects.filter(sha256=file_sha256)

    if len(p_queryset) > 0:
        if len(m_queryset) > 0:
            # filter out fields we don't want to show
            m = m_queryset[0].__dict__
            m.pop('_state')
            m.pop('id')

            # convert field names to labels, so that we show labels
            logger.debug("m={}".format(m))
            m_labels = {}
            for item in m.keys():
                # ensure we have a label
                if item in Malware.labels:
                    logger.debug("adding label={} value={}".format(Malware.labels[item], m[item]))
                    m_labels[Malware.labels[item]] = m[item]

            # same with properties: 1. filter out fields we don't want to show
            prop = p_queryset[0].__dict__
            toremove = ['_state', 'id', 'sha256']
            
            if not prop['packer_yes']:
                prop.pop('packer_name')
            if not prop['obfuscation_yes']:
                prop.pop('obfuscation_name')

            # we don't want to show any field which is False or empty
            for item in prop.keys():
                if prop[item] == False or prop[item]=='':
                    toremove.append(item)

            for i in toremove:
                prop.pop(i)

            # 2. show label names
            prop_labels = {}
            form = SelectForm()
            for item in prop.keys():
                if item != 'username' :
                    # username is an excluded field from the SelectForm
                    prop_labels[form.Meta.labels[item]] = prop[item]
                    logger.debug("show(): item={} label={} value={}".format(item, form.Meta.labels[item], prop[item]))

            logger.debug("show(): sample={}".format(m))
            logger.debug("show(): properties={}".format(prop_labels))

            context = { 'sample' : m_labels, 'properties' : prop_labels }
            return render(request, 'show.html', context)

    logger.warning("show(): cannot find sample - len_p={} len_m={} sha256={}".format(len(p_queryset), len(m_queryset), file_sha256))
    messages.error(request, 'We cant find sample with this SHA256: {}'.format(file_sha256))
    return HttpResponseRedirect(reverse('index'))

def edit(request, file_sha256):
    if  not belongs_to_group(request.user, 'poweruser') and not belongs_to_group(request.user, 'reviewer'):
        raise PermissionDenied
        
    p = Property.objects.filter(sha256=file_sha256)[0]
    form, validity = select_form(request, p)
    if validity:
        prop = form.save(commit=False)
        prop.sha256 = file_sha256
        prop.username = request.user.username
        logger.debug("edit(): property={}".format(prop))
        prop.save()

        return view(request)

    m = Malware.objects.filter(sha256=file_sha256)[0]
    context = { 'sample' : m, 'form' : form, 'toggle_categories' : get_toggle_categories(), 'message' : 'Edit properties of the malware' }
    logger.debug("edit(): rendering select for malware={}".format(m))
    return render(request, 'select.html', context)

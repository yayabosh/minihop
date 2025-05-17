from django import forms


class PcapUploadForm(forms.Form):
    pcap_file = forms.FileField(label="Select a .pcap file")

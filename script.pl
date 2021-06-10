#!/usr/bin/perl
# Indicare il path del file da voler analizzare tramite una sintassi ben precisa come argomento
# perl script.pl p=<file_path>
die "Assicurati di aver seguito correttamente la sintassi richiesta\n\nperl script.pl p=<file_path>\n" if($#ARGV < 0 or $#ARGV > 0);
@arg = split("p=", shift);
$path = $arg[1];
# print $path;

# Leggiamo il file di log salvando ogni riga in una determinata della dell'array log
@log = qx{cat $path};

# Verifichiamo in ogni riga se riscontriamo la notifica di tentato attacco, ovvero POSSIBLE BREAK-IN ATTEMPT!
# Se troviamo una riga corrispondente ci salviamo quella riga in un altro array Attacchi - potremmo fare già tutto qui però per essere più chiari suddivido in più pezzi

@attacchi;
for(@log){
    if(m/(POSSIBLE BREAK-IN ATTEMPT)/){
        push(@attacchi, $_);
    }
}
#print@attacchi;
# Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
#Regex per l'IP: \[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]
@tutti_gli_ip;
for(@attacchi){
    $_ =~ m/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/;
    push(@tutti_gli_ip,"$1\n");
}

# Elimino i duplicati
%tutti = ();
for (@tutti_gli_ip) {
    $tutti{$_}++;
}
@ip = keys %tutti;

# Salvo gli ip in un file blacklist
open(BLACKLIST,">","blacklist") or die $!;
print BLACKLIST @ip;
close BLACKLIST;

@analisi;
for(@ip){
    $tmp_ip = $_;
    @whois = qx{whois $tmp_ip};
    push(@analisi, "#####################################\n");
    push(@analisi, "# IP Rilevato: $tmp_ip");
    for(@whois){
        if($_ =~ m/(inetnum)/ or $_ =~ m/(netname)/){
            push(@analisi, "[NET] $_");
        }
        elsif($_ =~ m/(descr)/ or $_ =~ m/(organisation)/){
            push(@analisi, "[DESC] $_");
        }
        elsif($_ =~ m/(address)/ or $_ =~ m/(country)/){
            push(@analisi, "[GEO] $_");
        }
        elsif($_ =~ m/(mail)/ or $_ =~ m/(phone)/ or $_ =~ m/()/){
            push(@analisi, "[DATA] $_");
        }
    }
}

# Salvo gli ip in un file blacklist_data
open(BLACKLIST,">","blacklist_data") or die $!;
print BLACKLIST @analisi;
close BLACKLIST;
#!/usr/bin/env bash
#
# secret-scan.sh — SOC Lab repo için manuel literal-string secret taraması.
#
# NEDEN GEREKLİ: gitleaks'in varsayılan kuralları bilinen formatlı
# key'leri (AWS/GitHub/Slack tarzı regex) yakalar. Bu lab'daki secret'lar
# (rastgele UUID'ler, rastgele hex string'ler, özel karakter içeren
# şifreler) bilinen bir formata uymuyor — gitleaks bunları YAKALAMAZ.
# Bu script, bilinen secret'ları grep -F (fixed-string) ile literal
# olarak arar. -F kullanılıyor çünkü bazı secret'lar (*, + gibi regex
# özel karakteri içerenler) normal grep ile yanlış yorumlanır.
#
# ★ ÖNEMLİ TASARIM NOTU: Bu dosyanın kendisi HİÇBİR gerçek secret
# değeri İÇERMEZ — aradığı değerler ayrı, .gitignore'da olan
# `.secrets-known.sh` dosyasından okunur. Böylece bu script commit
# edilebilir (repo'da anlatılabilir bir metodoloji olarak) ama gerçek
# secret'lar asla git geçmişine girmez. Bir secret-tarama script'inin
# aradığı secret'ları kendi içinde taşıması, script'in kendisini bir
# sızıntı kaynağına çevirir — bu ayrım bilinçli bir tasarım kararı.
#
# ★ UYARI: Bu script SADECE METİN dosyalarını tarar. PNG/JPG
# screenshot'ların İÇİNDEKİ secret'ları TARAYAMAZ — bunlar için ayrı,
# manuel bir görsel denetimi gerekir.
#
# KULLANIM:
#   chmod +x secret-scan.sh
#   ./secret-scan.sh [taranacak_klasör]   (varsayılan: mevcut klasör)
#
# GEREKSİNİM: Bu script'le aynı klasörde `.secrets-known.sh` dosyası
# olmalı (git tarafından takip edilmez, .gitignore'da tanımlı). Bu
# dosya olmadan script çalışmaz.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$SCRIPT_DIR/.secrets-known.sh"

if [ ! -f "$SECRETS_FILE" ]; then
  echo "❌ HATA: $SECRETS_FILE bulunamadı."
  echo "   Bu dosya kasıtlı olarak git'e commit edilmiyor (.gitignore'da)."
  echo "   Taramayı çalıştırmak için önce bu dosyayı yerel olarak oluşturman gerekiyor."
  exit 1
fi

# shellcheck source=.secrets-known.sh
source "$SECRETS_FILE"

TARGET_DIR="${1:-.}"

FOUND=0

echo "=== secret-scan.sh — taranan klasör: $TARGET_DIR ==="
echo ""

for label in "${!SECRETS[@]}"; do
  value="${SECRETS[$label]}"
  # Sadece metin dosyalarını tara — binary'leri, .git'i, node_modules'ü,
  # ve script'in kendisiyle secrets dosyasını ATLA (aksi halde script
  # kendi kendini "buluyor" gibi görünür)
  matches=$(grep -rFn --binary-files=without-match \
    --exclude-dir=.git --exclude-dir=node_modules \
    --exclude="secret-scan.sh" --exclude=".secrets-known.sh" \
    -- "$value" "$TARGET_DIR" 2>/dev/null)

  if [ -n "$matches" ]; then
    FOUND=1
    echo "❌ BULUNDU: $label"
    echo "$matches" | while IFS= read -r line; do
      echo "    $line"
    done
    echo ""
  fi
done

echo "--------------------------------------------------------"
if [ "$FOUND" -eq 0 ]; then
  echo "✅ Bilinen tüm secret'lar için temiz sonuç (metin dosyalarında)."
else
  echo "⚠️  Yukarıdaki secret'ları redakte et ve tekrar çalıştır."
fi
echo ""
echo "★ HATIRLATMA: Bu script PNG/JPG screenshot'ları TARAMADI."
echo "  Ekran görüntülerini elle kontrol et."

exit $FOUND
# وصف أعمدة داتا سيت CICIDS-2017

**المصدر:** `bvk/CICIDS-2017` على Hugging Face
**الحجم:** حوالي 2.1 مليون صف (Flow) × حوالي 90 عمود
**نوع المشكلة:** Network Intrusion Detection (تصنيف Binary أو Multi-class)

---

## 1) نبذة عن الداتا

- الداتا اتجمعت على مدار 5 أيام (من الإثنين للجمعة). الإثنين غالبه Traffic سليم (Benign)، وباقي الأيام فيها هجمات: Brute Force (FTP/SSH)، أنواع DoS/DDoS، Botnet، Infiltration، Port Scan، Web Attacks.
- الـ PCAP الخام اتحول لـ **Flows** باستخدام أداة **CICFlowMeter**.
- **الـ Flow** يعني: مجموعة Packets بين نفس الـ Source/Destination (IP + Port + Protocol). الـ TCP flow بينتهي بإغلاق الاتصال، والـ UDP بينتهي بـ timeout.
- النسخة دي هي النسخة المصححة (Engelen et al., 2021) اللي صلحت أخطاء في CICFlowMeter وأعادت تصنيف بعض العينات، مع إضافة الـ IP كأرقام decimal وحذف الصفوف اللي فيها `inf`.

> **اصطلاحات مهمة في أسماء الأعمدة:**
> - **Fwd** = الاتجاه من الـ Client (اللي بدأ الاتصال) للـ Server.
> - **Bwd** = الاتجاه العكسي (من الـ Server للـ Client).
> - **IAT** = Inter-Arrival Time، أي الزمن بين وصول Packet والتانية (بالـ microseconds).
> - الأزمنة كلها بالـ **microseconds** (µs) غالبًا.

---

## 2) أعمدة تعريف الاتصال (Identifiers)

| العمود | النوع | الوصف |
|---|---|---|
| `Src IP dec` | int | عنوان الـ IP للمصدر محوّل لرقم decimal |
| `Src Port` | int | بورت المصدر |
| `Dst IP dec` | int | عنوان الـ IP للوجهة محوّل لرقم decimal |
| `Dst Port` | int | بورت الوجهة (مفيد جدًا: 80, 443, 22, 21, 53...) |
| `Protocol` | int | رقم البروتوكول: 6 = TCP، 17 = UDP، 1 = ICMP، 0 = HOPOPT |
| `Timestamp` | string | وقت بداية الـ Flow (شوف التحذير في قسم المشاكل) |

---

## 3) أعمدة المدة والحجم العام

| العمود | الوصف |
|---|---|
| `Flow Duration` | مدة الـ Flow كاملة (µs) |
| `Total Fwd Packet` | إجمالي عدد الـ Packets في الاتجاه Fwd |
| `Total Bwd packets` | إجمالي عدد الـ Packets في الاتجاه Bwd |
| `Total Length of Fwd Packet` | إجمالي حجم الـ Payload بالـ bytes في Fwd |
| `Total Length of Bwd Packet` | إجمالي حجم الـ Payload بالـ bytes في Bwd |
| `Total TCP Flow Time` | إجمالي زمن الـ TCP flow (ميزة إضافية في النسخة المصححة) |

---

## 4) أعمدة أطوال الـ Packets

### في اتجاه Fwd
| العمود | الوصف |
|---|---|
| `Fwd Packet Length Max` | أكبر Packet |
| `Fwd Packet Length Min` | أصغر Packet |
| `Fwd Packet Length Mean` | المتوسط |
| `Fwd Packet Length Std` | الانحراف المعياري |

### في اتجاه Bwd
| العمود | الوصف |
|---|---|
| `Bwd Packet Length Max` | أكبر Packet |
| `Bwd Packet Length Min` | أصغر Packet |
| `Bwd Packet Length Mean` | المتوسط |
| `Bwd Packet Length Std` | الانحراف المعياري |

### على مستوى الـ Flow كله
| العمود | الوصف |
|---|---|
| `Packet Length Min` | أصغر Packet في الـ Flow |
| `Packet Length Max` | أكبر Packet في الـ Flow |
| `Packet Length Mean` | متوسط طول الـ Packets |
| `Packet Length Std` | الانحراف المعياري |
| `Packet Length Variance` | التباين (Variance) |
| `Average Packet Size` | متوسط حجم الـ Packet |
| `Fwd Segment Size Avg` | متوسط حجم الـ Segment في Fwd |
| `Bwd Segment Size Avg` | متوسط حجم الـ Segment في Bwd |

---

## 5) أعمدة السرعة (Rates)

| العمود | الوصف |
|---|---|
| `Flow Bytes/s` | عدد الـ bytes في الثانية للـ Flow كله |
| `Flow Packets/s` | عدد الـ Packets في الثانية للـ Flow كله |
| `Fwd Packets/s` | معدل الـ Packets في اتجاه Fwd |
| `Bwd Packets/s` | معدل الـ Packets في اتجاه Bwd |
| `Down/Up Ratio` | نسبة الـ Download للـ Upload (Bwd/Fwd) |

---

## 6) أعمدة الزمن بين الـ Packets (IAT)

### على مستوى الـ Flow
| العمود | الوصف |
|---|---|
| `Flow IAT Mean` | متوسط الزمن بين أي Packetين متتاليين |
| `Flow IAT Std` | الانحراف المعياري |
| `Flow IAT Max` | أكبر فجوة زمنية |
| `Flow IAT Min` | أصغر فجوة زمنية |

### في اتجاه Fwd
| العمود | الوصف |
|---|---|
| `Fwd IAT Total` | مجموع الأزمنة بين Packets الـ Fwd |
| `Fwd IAT Mean` / `Fwd IAT Std` / `Fwd IAT Max` / `Fwd IAT Min` | إحصائيات الأزمنة في Fwd |

### في اتجاه Bwd
| العمود | الوصف |
|---|---|
| `Bwd IAT Total` | مجموع الأزمنة بين Packets الـ Bwd |
| `Bwd IAT Mean` / `Bwd IAT Std` / `Bwd IAT Max` / `Bwd IAT Min` | إحصائيات الأزمنة في Bwd |

---

## 7) أعمدة الـ TCP Flags

### Flags حسب الاتجاه
| العمود | الوصف |
|---|---|
| `Fwd PSH Flags` | عدد مرات ظهور PSH في Fwd |
| `Bwd PSH Flags` | عدد مرات ظهور PSH في Bwd |
| `Fwd URG Flags` | عدد مرات ظهور URG في Fwd |
| `Bwd URG Flags` | عدد مرات ظهور URG في Bwd |
| `Fwd RST Flags` | عدد مرات ظهور RST في Fwd |
| `Bwd RST Flags` | عدد مرات ظهور RST في Bwd |

### إجمالي الـ Flags في الـ Flow
| العمود | الوصف |
|---|---|
| `FIN Flag Count` | عدد الـ FIN (إنهاء الاتصال) |
| `SYN Flag Count` | عدد الـ SYN (بدء الاتصال، مهم لكشف SYN Flood/Port Scan) |
| `RST Flag Count` | عدد الـ RST (قطع الاتصال بشكل مفاجئ) |
| `PSH Flag Count` | عدد الـ PSH |
| `ACK Flag Count` | عدد الـ ACK |
| `URG Flag Count` | عدد الـ URG |
| `CWR Flag Count` | عدد الـ CWR (Congestion Window Reduced) |
| `ECE Flag Count` | عدد الـ ECE (ECN Echo) |

---

## 8) أعمدة الـ Header والـ Window

| العمود | الوصف |
|---|---|
| `Fwd Header Length` | إجمالي حجم الـ Headers في Fwd (bytes) |
| `Bwd Header Length` | إجمالي حجم الـ Headers في Bwd (bytes) |
| `FWD Init Win Bytes` | حجم الـ TCP Window المبدئي في Fwd |
| `Bwd Init Win Bytes` | حجم الـ TCP Window المبدئي في Bwd |
| `Fwd Act Data Pkts` | عدد Packets الـ Fwd اللي فيها Data فعلية (Payload > 0) |
| `Fwd Seg Size Min` | أصغر حجم Segment في Fwd |

---

## 9) أعمدة الـ Bulk والـ Subflow

### Bulk (إرسال بيانات متتالية بسرعة)
| العمود | الوصف |
|---|---|
| `Fwd Bytes/Bulk Avg` | متوسط الـ bytes في الـ Bulk (Fwd) |
| `Fwd Packet/Bulk Avg` | متوسط عدد الـ Packets في الـ Bulk (Fwd) |
| `Fwd Bulk Rate Avg` | معدل الـ Bulk (Fwd) |
| `Bwd Bytes/Bulk Avg` | متوسط الـ bytes في الـ Bulk (Bwd) |
| `Bwd Packet/Bulk Avg` | متوسط عدد الـ Packets في الـ Bulk (Bwd) |
| `Bwd Bulk Rate Avg` | معدل الـ Bulk (Bwd) |

### Subflow
| العمود | الوصف |
|---|---|
| `Subflow Fwd Packets` | عدد Packets الـ Subflow في Fwd |
| `Subflow Fwd Bytes` | عدد bytes الـ Subflow في Fwd |
| `Subflow Bwd Packets` | عدد Packets الـ Subflow في Bwd |
| `Subflow Bwd Bytes` | عدد bytes الـ Subflow في Bwd |

---

## 10) أعمدة النشاط والخمول (Active / Idle)

الـ Flow بيتقسم لفترات **نشاط** (فيها Packets) وفترات **خمول** (مفيش Packets).

| العمود | الوصف |
|---|---|
| `Active Mean` / `Active Std` / `Active Max` / `Active Min` | إحصائيات فترات النشاط |
| `Idle Mean` / `Idle Std` / `Idle Max` / `Idle Min` | إحصائيات فترات الخمول |

---

## 11) أعمدة ICMP

| العمود | الوصف |
|---|---|
| `ICMP Code` | كود الـ ICMP (القيمة `-1` = مش ICMP) |
| `ICMP Type` | نوع الـ ICMP (القيمة `-1` = مش ICMP) |

---

## 12) أعمدة التصنيف (Targets)

| العمود | الوصف |
|---|---|
| `Label` | **الـ Target الأساسي.** نوع الـ Traffic: `BENIGN` أو نوع الهجوم. الـ Viewer بيوضح إن فيه **27 قيمة مختلفة** |
| `Attempted Category` | عمود إضافي من النسخة المصححة. القيمة `-1` معناها مفيش محاولة هجوم، والقيم من `0` لـ `6` بتدل على فئة هجوم "محاولة". **مش متأكد من الـ mapping بين الأرقام والفئات، راجعها بـ `value_counts()` مع `Label`** |

> **ملاحظة:** وصف الداتا بيقول 16 فئة (Benign + 15 هجوم) بس الـ Viewer بيعرض 27 قيمة في `Label`. غالبًا الفرق من إعادة التصنيف في النسخة المصححة (ممكن تظهر قيم زي "Attempted" لبعض الهجمات). اتأكد منها بـ `df['Label'].value_counts()` قبل ما تبني الـ Model.

---

## 13) الأعمدة اللي بينها علاقة (Redundancy / Multicollinearity)

دي أهم نقطة للـ Feature Selection. في أعمدة مشتقة من بعض رياضيًا أو شبه مكررة:

### علاقات رياضية مؤكدة (تحققت منها من عينة الصفوف)

| العلاقة                                                                                                | الشرح                         |
| ------------------------------------------------------------------------------------------------------ | ----------------------------- |
| `Packet Length Variance` = `Packet Length Std`²                                                        | نفس المعلومة، احذف واحد منهم  |
| `Flow Packets/s` = (`Total Fwd Packet` + `Total Bwd packets`) ÷ `Flow Duration` × 10⁶                  | مشتق من 3 أعمدة تانية         |
| `Flow Bytes/s` = (`Total Length of Fwd Packet` + `Total Length of Bwd Packet`) ÷ `Flow Duration` × 10⁶ | مشتق من 3 أعمدة تانية         |
| `Fwd Packets/s` = `Total Fwd Packet` ÷ `Flow Duration` × 10⁶                                           | نفس الفكرة                    |
| `Bwd Packets/s` = `Total Bwd packets` ÷ `Flow Duration` × 10⁶                                          | نفس الفكرة                    |
| `Fwd Segment Size Avg` = `Fwd Packet Length Mean`                                                      | متطابقين في العينة اللي شفتها |
| `Bwd Segment Size Avg` = `Bwd Packet Length Mean`                                                      | متطابقين في العينة اللي شفتها |
| `Down/Up Ratio` = `Total Bwd packets` ÷ `Total Fwd Packet`                                             | نسبة جاهزة (تقريبًا)          |

### علاقات قوية جدًا (Correlation عالية متوقعة)

| المجموعة | ليه مرتبطين |
|---|---|
| `Average Packet Size` و `Packet Length Mean` | بيقيسوا تقريبًا نفس الحاجة |
| `Fwd IAT Total` و `Flow Duration` | مجموع أزمنة Fwd قريب من مدة الـ Flow كلها |
| `Flow IAT Max` و `Idle Max` و `Fwd IAT Max` | أكبر فجوة زمنية بتظهر في كلهم |
| `Fwd IAT Mean` و `Fwd IAT Std` و `Fwd IAT Max` (وكذلك Bwd) | إحصائيات من نفس التوزيع |
| `Total Fwd Packet` و `Subflow Fwd Packets` | نفس العدد تقريبًا في الداتا الأصلية |
| `Total Length of Fwd Packet` و `Subflow Fwd Bytes` | نفس الفكرة |
| `Total Bwd packets` و `Subflow Bwd Packets` | نفس الفكرة |
| `Total Length of Bwd Packet` و `Subflow Bwd Bytes` | نفس الفكرة |
| `Fwd Header Length` و `Total Fwd Packet` | الـ Header ثابت تقريبًا لكل Packet، فالحجم بيزيد مع العدد |
| `Bwd Header Length` و `Total Bwd packets` | نفس الفكرة |
| `Fwd Packet Length Max` و `Packet Length Max` | الـ Max الكلي غالبًا بييجي من Fwd أو Bwd |
| `Active Max` / `Active Mean` / `Active Min` | بيتحركوا مع بعض لما الـ Flow فيه فترة نشاط واحدة |
| `Idle Mean` / `Idle Max` / `Idle Min` | نفس الفكرة |
| `Fwd PSH Flags` و `PSH Flag Count` | الـ Flag Count الكلي = مجموع Fwd + Bwd تقريبًا |
| `Fwd RST Flags` + `Bwd RST Flags` و `RST Flag Count` | نفس الفكرة |
| `Fwd URG Flags` + `Bwd URG Flags` و `URG Flag Count` | نفس الفكرة |

### علاقات منطقية (مش رياضية)

| العلاقة | الشرح |
|---|---|
| `Protocol` و `ICMP Code`/`ICMP Type` | الـ ICMP columns ليها قيمة فقط لما Protocol = 1، غير كده بتبقى `-1` |
| `Protocol` و TCP Flags / `Init Win Bytes` / `Total TCP Flow Time` | دول بيكون ليهم معنى بس مع TCP (Protocol = 6) |
| `Label` و `Attempted Category` | `Attempted Category` مشتق من تصنيف الهجوم، فهو **Data Leakage** لو دخل الـ Features |
| `Dst Port` و `Label` | بعض الهجمات مربوطة ببورت معين (SSH:22، FTP:21، Web:80) |

---

## 14) مشاكل لازم تتعامل معاها في الـ Preprocessing

1. **`Timestamp`**: الـ Viewer بيوضح إن كل القيم طولها 7 حروف (شكلها زي `59:50.3`)، يعني فقدت التاريخ والساعة وبقت دقائق:ثواني بس. **مش قابلة للاستخدام كوقت حقيقي** ولا لعمل Time-based split. الأفضل تشيلها.
2. **Data Leakage (احذفهم من الـ Features):**
   - `Attempted Category` (مشتق من الـ Label).
   - `Src IP dec` و `Dst IP dec`: الموديل هيحفظ عناوين المهاجم/الضحية بدل ما يتعلم السلوك، وهيبقى ضعيف على شبكة تانية.
   - `Src Port` غالبًا عشوائي ومش مفيد (Ephemeral port).
3. **قيم سالبة غير منطقية:** `Fwd Header Length` و `Bwd Header Length` فيهم قيم سالبة (الـ Viewer بيوضح قيم زي −32,708). ده Integer Overflow من CICFlowMeter. التعامل: تحويلها لـ NaN أو تصفيرها أو حذف الصفوف.
4. **قيم سالبة تانية:** `Subflow Bwd Bytes` / `Bwd Init Win Bytes` ممكن يكون فيهم قيم سالبة في بعض الصفوف. اتأكد بـ `df.describe()`.
5. **`Flow Bytes/s` و `Flow Packets/s`**: ممكن يكون فيهم قيم ضخمة جدًا أو NaN/Inf لما `Flow Duration` صغيرة جدًا. اعمل `replace([np.inf, -np.inf], np.nan)`.
6. **أعمدة شبه ثابتة (Zero/Low Variance):** أعمدة زي `Fwd URG Flags` و `Bwd URG Flags` و `Bwd PSH Flags` و `Bulk` columns أغلبها أصفار. افحصها بـ `df.nunique()` وشيل الثابت منها.
7. **Skewness عالي:** أغلب الأعمدة الرقمية (Duration, Packets, Bytes, IAT) توزيعها مائل جدًا. استخدم `log1p` أو `RobustScaler`/`QuantileTransformer`.
8. **Class Imbalance:** غالبًا الـ `BENIGN` و `DoS Hulk` و `DDoS` و `PortScan` هم الأغلبية، وهجمات زي `Heartbleed` و `SQL Injection` و `Infiltration` نادرة جدًا. استخدم Stratified split و class weights أو SMOTE/Undersampling، ومتعتمدش على الـ Accuracy، استخدم Macro-F1 و Recall لكل Class.
9. **صفوف مكررة:** اعمل `df.duplicated().sum()` وقرر تحذفها قبل الـ Split عشان متحصلش تسريب بين Train و Test.
10. **الإحصائيات اللي في الـ Hugging Face Viewer** (min/max) متحسبة غالبًا على جزء بس من الداتا، فاعمل EDA كامل على الداتا كلها بنفسك.

---

## 15) كود جاهز للبداية

```python
import pandas as pd
import numpy as np
from datasets import load_dataset

ds = load_dataset("bvk/CICIDS-2017", split="train")
df = ds.to_pandas()

# تنظيف أولي
df.columns = df.columns.str.strip()
df = df.replace([np.inf, -np.inf], np.nan)

# فحص التارجت
print(df["Label"].value_counts())
print(pd.crosstab(df["Label"], df["Attempted Category"]))

# شيل أعمدة التسريب/الغير مفيدة
drop_cols = ["Timestamp", "Src IP dec", "Dst IP dec", "Src Port", "Attempted Category"]
X = df.drop(columns=drop_cols + ["Label"])
y = df["Label"]

# شيل الأعمدة الثابتة
X = X.loc[:, X.nunique() > 1]

# شيل الأعمدة المكررة (corr > 0.95)
corr = X.corr().abs()
upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
to_drop = [c for c in upper.columns if (upper[c] > 0.95).any()]
X = X.drop(columns=to_drop)
print(f"Dropped {len(to_drop)} highly correlated columns")
```

<?php
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
use FireflyIII\Models\Account; use FireflyIII\Models\Note; use FireflyIII\User; use Illuminate\Support\Facades\Auth;
foreach ([['AVA (granted)',1],['SAM (ungranted)',2],['NO READER',null]] as [$label,$uid]) {
    Auth::logout();
    if (null !== $uid) { Auth::login(User::find($uid)); }
    $a = Account::find(1);
    $n = Note::where('noteable_id',1)->orderBy('id')->first();
    echo "$label: name={$a->name} | iban={$a->iban} | note=".substr((string)($n->text??''),0,55)."\n";
}

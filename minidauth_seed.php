<?php

// Seeds a minimal Firefly III demo and prints the raw SQLite values, to prove minidauth sealing.
require '/app/vendor/autoload.php';
$app = require '/app/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();

use FireflyIII\Models\Account;
use FireflyIII\Models\AccountType;
use FireflyIII\Models\GroupMembership;
use FireflyIII\Models\Note;
use FireflyIII\Models\UserGroup;
use FireflyIII\Models\UserRole;
use FireflyIII\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

function makeUser(string $email): User
{
    $u = User::where('email', $email)->first();
    if (null === $u) {
        $g = UserGroup::create(['title' => $email]);
        $u = User::create(['email' => $email, 'password' => Hash::make('Password1!')]);
        $u->user_group_id = $g->id;
        $u->save();
        $role = UserRole::where('title', 'owner')->first();
        if (null !== $role) {
            GroupMembership::create(['user_id' => $u->id, 'user_group_id' => $g->id, 'user_role_id' => $role->id]);
        }
    }
    return $u;
}

$ava = makeUser('ava@demo.com');   // will be GRANTED crm-reader
$sam = makeUser('sam@demo.com');   // ungranted control

$expense = AccountType::where('type', 'Expense account')->first();

$acct = Account::where('user_id', $ava->id)->where('account_type_id', $expense->id)->first();
if (null === $acct) {
    $acct                 = new Account();
    $acct->user_id        = $ava->id;
    $acct->user_group_id  = $ava->user_group_id;
    $acct->account_type_id = $expense->id;
    $acct->name           = 'Jordan Holdings LLC';
    $acct->iban           = 'GB29NWBK60161331926819';
    $acct->active         = true;
    $acct->save();

    $note               = new Note();
    $note->noteable_id  = $acct->id;
    $note->noteable_type = Account::class;
    $note->text         = 'Recurring vendor for the Q3 audit engagement, ref 8842.';
    $note->save();
}

$rawA = DB::connection()->getPdo()->query("SELECT name, iban FROM accounts WHERE id = {$acct->id}")->fetch(PDO::FETCH_ASSOC);
$rawN = DB::connection()->getPdo()->query("SELECT text FROM notes WHERE noteable_id = {$acct->id} ORDER BY id LIMIT 1")->fetch(PDO::FETCH_ASSOC);

echo "AVA_ID={$ava->id}\n";
echo "SAM_ID={$sam->id}\n";
echo "ACCT_ID={$acct->id}\n";
echo 'RAW_DB name=' . substr((string) $rawA['name'], 0, 26) . ' iban=' . substr((string) $rawA['iban'], 0, 20) . "\n";
echo 'RAW_DB note=' . substr((string) ($rawN['text'] ?? ''), 0, 26) . "\n";
